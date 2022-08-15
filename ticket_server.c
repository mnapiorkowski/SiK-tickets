/*
 * Michał Napiórkowski
 * SIK 2021/22 - task 1
 * UDP/IPv4 server for tickets reservation
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <time.h>
#include <malloc.h>
#include <getopt.h>

#define DEFAULT_PORT 2022
#define DEFAULT_TIMEOUT 5

#define GET_EVENTS 1
#define EVENTS 2
#define GET_RESERVATION 3
#define RESERVATION 4
#define GET_TICKETS 5
#define TICKETS 6
#define BAD_REQUEST 255

#define MESSAGE_ID_SIZE 1
#define DESCRIPTION_LENGTH_SIZE 1
#define TICKET_COUNT_SIZE 2
#define EVENT_ID_SIZE 4
#define RESERVATION_ID_SIZE 4
#define COOKIE_SIZE 48
#define EXPIRATION_TIME_SIZE 8
#define TICKET_SIZE 7

#define BUF_SIZE 65507 // max UDP datagram size
#define MAX_TICKETS_PER_RESERVATION (BUF_SIZE - MESSAGE_ID_SIZE - RESERVATION_ID_SIZE - TICKET_COUNT_SIZE) / TICKET_SIZE
#define MAX_TIMEOUT 86400
#define MAX_EVENT_ID 999999
#define MIN_RESERVATION_ID MAX_EVENT_ID + 1
#define MAX_LINE_LENGTH 80
#define MIN_COOKIE_CHAR 33
#define MAX_COOKIE_CHAR 126
#define USAGE "Usage: %s -f <file> (-p <port> -t <timeout>)"

typedef struct {
    uint32_t id;
    uint8_t description_length;
    char description[MAX_LINE_LENGTH + 1];
    uint16_t tickets_available;
} event_t;

typedef struct {
    char code[TICKET_SIZE + 1];
} ticket_t;

typedef struct {
    uint32_t id;
    uint32_t event_id;
    uint16_t ticket_count;
    ticket_t* tickets;
    char cookie[COOKIE_SIZE + 1];
    time_t expiration_time;
    bool cancelled;
    bool sent;
} reservation_t;

// >>> Handling errors <<<
// Code from err.h in laboratory scenarios.

#define PRINT_ERRNO()                                                  \
    do {                                                               \
        if (errno != 0) {                                              \
            fprintf(stderr, "Error: errno %d in %s at %s:%d\n%s\n",    \
              errno, __func__, __FILE__, __LINE__, strerror(errno));   \
            exit(EXIT_FAILURE);                                        \
        }                                                              \
    } while (0)

void fatal(const char *fmt, ...) {
    va_list fmt_args;
    fprintf(stderr, "Error: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

// >>> Files and sockets <<<

FILE* open_file(char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fatal("could not open '%s'", filename);
    }
    return f;
}

void close_file(FILE* file, char* filename) {
    if (fclose(file) != 0) {
        fatal("could not close '%s'", filename);
    }
}

int new_socket() {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }
    return socket_fd;
}

void close_socket(int socket_fd) {
    if (close(socket_fd) < 0) {
        PRINT_ERRNO();
    }
}

void bind_socket(int socket_fd, uint16_t port) {
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    if (bind(socket_fd, (struct sockaddr*) &server_address,
             (socklen_t) sizeof(server_address)) != 0) {
        PRINT_ERRNO();
    }
}

// >>> Other useful functions <<<

// big-endian buffer -> little-endian uint64
uint64_t uint_from_buffer(unsigned char* buffer, size_t* buf_curr, int size) {
    uint64_t x = 0;
    for (int i = size - 1; i >= 0; i--) {
        x |= buffer[(*buf_curr)++] << (i * 8);
    }
    return x;
}

// little-endian uint64 -> big-endian buffer
void uint_to_buffer(unsigned char* buffer, size_t* buf_end, uint64_t x, int size) {
    for (int i = size - 1; i >= 0; i--) {
        buffer[(*buf_end)++] = x >> (i * 8);
    }
}

void* new_array(size_t size, size_t sizeof_type) {
    void* array = malloc(size * sizeof_type);
    if (array == NULL) {
        fatal("malloc failed");
    }
    return array;
}

void resize_array(void** array, size_t count, size_t* size, size_t sizeof_type) {
    if (*size == count) {
        (*size) *= 2;
        (*size)++;
        *array = realloc(*array, (*size) * sizeof_type);
        if (*array == NULL) {
            fatal("realloc failed");
        }
    }
}

// >>> Parsing arguments <<<

uint16_t read_port(char* str) {
    char* endptr;
    unsigned long port = strtoul(str, &endptr, 10);
    if (port == ULONG_MAX) {
        PRINT_ERRNO();
    }
    if (port > UINT16_MAX || *endptr != 0) {
        fatal("'%s' is not a valid port number", str);
    }
    return (uint16_t) port;
}

time_t read_timeout(char* str) {
    char* endptr;
    unsigned long timeout = strtoul(str, &endptr, 10);
    if (timeout == ULONG_MAX) {
        PRINT_ERRNO();
    }
    if (timeout < 1 || timeout > MAX_TIMEOUT || *endptr != 0) {
        fatal("'%s' is not a valid timeout value", str);
    }
    return (time_t) timeout;
}

void parse_arguments(int argc, char* argv[], char** filename, uint16_t* port, time_t* timeout) {
    int opt;
    char* port_str = NULL;
    char* timeout_str = NULL;
    while ((opt = getopt(argc, argv, ":f:p:t:")) != -1) {
        switch (opt) {
            case 'f':
                *filename = optarg;
                break;
            case 'p':
                port_str = optarg;
                break;
            case 't':
                timeout_str = optarg;
                break;
            case ':':
                fatal("option '-%c' requires an operand\n" USAGE, optopt);
            case '?':
                fatal("unknown option '-%c'\n" USAGE, optopt);
        }
    }
    if (optind < argc) {
        fatal("argument '%s' is not a valid option\n" USAGE, argv[optind]);
    }
    if (*filename == NULL) {
        fatal("filename was not specified\n" USAGE, argv[0]);
    }
    if (port_str != NULL) {
        *port = read_port(port_str);
    } else {
        *port = DEFAULT_PORT;
    }
    if (timeout_str != NULL) {
        *timeout = read_timeout(timeout_str);
    } else {
        *timeout = DEFAULT_TIMEOUT;
    }
}

// >>> Exchanging messages <<<

size_t read_message(int socket_fd, struct sockaddr_in* client_address, unsigned char* buffer, size_t max_length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    ssize_t read_len = recvfrom(socket_fd, buffer, max_length, 0,
                           (struct sockaddr*) client_address, &address_length);
    if (read_len < 0) {
        PRINT_ERRNO();
    }
    return (size_t) read_len;
}

void send_message(int socket_fd, const struct sockaddr_in* client_address, const unsigned char* message, size_t length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    ssize_t sent_len = sendto(socket_fd, message, length, 0,
                                 (struct sockaddr*) client_address, address_length);
    if (sent_len < 0) {
        PRINT_ERRNO();
    }
}

// >>> Generating unique values <<<
// Cookie is completely random, other use values passed as argument.

uint32_t next_event_id(uint32_t event_id) {
    return (event_id + 1) % (MAX_EVENT_ID + 1);
}

uint32_t next_reservation_id(uint32_t reservation_id) {
    if (reservation_id == UINT32_MAX) {
        return MIN_RESERVATION_ID;
    } else {
        return reservation_id + 1;
    }
}

void generate_ticket_code(char* code) {
    for (int i = TICKET_SIZE - 1; i >= 0; i--) {
        if (code[i] == 'Z') {
            code[i] = '0';
        } else if (code[i] == '9') {
            code[i] = 'A';
            return;
        } else {
            code[i]++;
            return;
        }
    }
}

void generate_cookie(char* cookie) {
    for (int i = 0; i < COOKIE_SIZE; i++) {
        int r = rand() % (MAX_COOKIE_CHAR + 1 - MIN_COOKIE_CHAR) + MIN_COOKIE_CHAR;
        cookie[i] = (char) r;
    }
    cookie[COOKIE_SIZE] = 0;
}

// >>> Operations on event_t, reservation_t and ticket_t structures <<<

event_t* find_event(event_t* events, size_t count, uint32_t id) {
    for (size_t i = 0; i < count; i++) {
        if (events[i].id == id) {
            return &events[i];
        }
    }
    return NULL;
}

reservation_t* find_reservation(reservation_t * reservations, size_t count, uint32_t id) {
    for (size_t i = 0; i < count; i++) {
        if (reservations[i].id == id) {
            return &reservations[i];
        }
    }
    return NULL;
}

size_t read_events(FILE* file, event_t** events) {
    char line[MAX_LINE_LENGTH + 2]; // 80 + '\n' + '\0'
    uint32_t id = 0;
    bool even = true; // is line number even (counting from 1)
    size_t events_size = 1;
    size_t count = 0;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // get rid of '\n'
        even = !even;
        if (!even) {
            (*events)[count].description_length = strlen(line);
            strcpy((*events)[count].description, line);
        } else {
            unsigned long tickets = strtoul(line, NULL, 10);
            if (tickets == ULONG_MAX) {
                PRINT_ERRNO();
            }

            id = next_event_id(id);
            (*events)[count].id = id;
            (*events)[count].tickets_available = (uint16_t) tickets;

            count++;
            resize_array((void**) events, count, &events_size, sizeof(event_t));
        }
    }
    return count;
}

reservation_t* new_reservation(reservation_t** reservations, size_t* count, size_t* size,
                               uint32_t event_id, uint16_t ticket_count, time_t expiration_time) {
    if (*count == 0) {
        (*reservations)[*count].id = MIN_RESERVATION_ID;
    } else {
        (*reservations)[*count].id = next_reservation_id((*reservations)[*count - 1].id);
    }

    (*reservations)[*count].event_id = event_id;
    (*reservations)[*count].ticket_count = ticket_count;
    (*reservations)[*count].tickets = NULL;
    (*reservations)[*count].expiration_time = expiration_time;
    (*reservations)[*count].cancelled = false;
    (*reservations)[*count].sent = false;

    char cookie[COOKIE_SIZE + 1];
    generate_cookie(cookie);
    strcpy((*reservations)[*count].cookie, cookie);

    (*count)++;
    resize_array((void**) reservations, *count, size, sizeof(reservation_t));
    return &(*reservations)[*count - 1];
}

void generate_tickets(reservation_t* r, char* ticket_code) {
    if (!r->sent) {
        r->tickets = new_array(r->ticket_count, sizeof(ticket_t));
        for (uint16_t i = 0; i < r->ticket_count; i++) {
            generate_ticket_code(ticket_code);
            strcpy(r->tickets[i].code, ticket_code);
        }
    }
}

void change_tickets_available(event_t* event, uint16_t ticket_count, bool add) {
    if (add) {
        event->tickets_available += ticket_count;
    } else {
        event->tickets_available -= ticket_count;
    }
}

void free_tickets(reservation_t* reservations, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (reservations[i].tickets != NULL) {
            free(reservations[i].tickets);
        }
    }
}

void cancel_expired_reservations(reservation_t* reservations, size_t reservations_count, event_t* events, size_t events_count) {
    for (size_t i = 0; i < reservations_count; i++) {
        if (!reservations[i].cancelled && !reservations[i].sent && reservations[i].expiration_time <= time(NULL)) {
            change_tickets_available(find_event(events, events_count, reservations[i].event_id),
                                     reservations[i].ticket_count, true);
            reservations[i].cancelled = true;
        }
    }
}

// >>> Checking correctness of received messages <<<

uint8_t get_message_id(unsigned char* message, size_t length) {
    uint8_t id = 0;
    if (length > 0) {
        id = message[0];
        if (id != GET_EVENTS && id != GET_RESERVATION && id != GET_TICKETS) {
            id = 0;
        }
    }
    return id; // 0 -> incorrect length or id of the message -> server ignores it
}

bool get_events_length_ok(size_t message_len) {
    return message_len == MESSAGE_ID_SIZE;
}

bool get_reservation_length_ok(size_t message_len) {
    return message_len == MESSAGE_ID_SIZE + EVENT_ID_SIZE + TICKET_COUNT_SIZE;
}

bool get_tickets_length_ok(size_t message_len) {
    return message_len == MESSAGE_ID_SIZE + RESERVATION_ID_SIZE + COOKIE_SIZE;
}

bool get_reservation_correct(unsigned char* message, uint32_t* event_id, uint16_t* ticket_count,
                             event_t* events, size_t events_count, event_t** event) {
    size_t buf_curr = 1;
    *event_id = (uint32_t) uint_from_buffer(message, &buf_curr, EVENT_ID_SIZE);
    *ticket_count = (uint16_t) uint_from_buffer(message, &buf_curr, TICKET_COUNT_SIZE);
    if (*event_id > MAX_EVENT_ID || *ticket_count == 0 || *ticket_count > MAX_TICKETS_PER_RESERVATION) {
        return false;
    }

    *event = find_event(events, events_count, *event_id);
    if (!(*event) || (*event)->tickets_available < *ticket_count) {
        return false;
    }
    return true;
}

bool get_tickets_correct(unsigned char* message, uint32_t* reservation_id, reservation_t* reservations,
                         size_t reservations_count, reservation_t** reservation) {
    size_t buf_curr = 1;
    *reservation_id = (uint32_t) uint_from_buffer(message, &buf_curr, RESERVATION_ID_SIZE);
    if (*reservation_id < MIN_RESERVATION_ID) {
        return false;
    }

    *reservation = find_reservation(reservations, reservations_count, *reservation_id);
    if (!(*reservation) || (*reservation)->cancelled) {
        return false;
    }

    char cookie[COOKIE_SIZE + 1];
    for (size_t i = 0; i < COOKIE_SIZE; i++) {
        cookie[i] = message[buf_curr++];
    }
    cookie[COOKIE_SIZE] = 0;
    if (strcmp((*reservation)->cookie, cookie) != 0) {
        return false;
    }
    return true;
}

// >>> Building messages <<<
// Functions build_*_message put adequate message into the buffer and return length of this message.

void clear_buffer(unsigned char* buffer) {
    memset(buffer, 0, BUF_SIZE);
}

size_t build_events_message(unsigned char* buffer, event_t* events, size_t events_count) {
    clear_buffer(buffer);
    buffer[0] = EVENTS;
    size_t buf_end = 1;
    size_t free_space = BUF_SIZE - 1;

    for (size_t i = 0; i < events_count && free_space > 0; i++) {
        event_t e = events[i];
        size_t event_size = EVENT_ID_SIZE + TICKET_COUNT_SIZE +
                            DESCRIPTION_LENGTH_SIZE + e.description_length;
        if (free_space >= event_size) {
            uint_to_buffer(buffer, &buf_end, e.id, EVENT_ID_SIZE);
            uint_to_buffer(buffer, &buf_end, e.tickets_available, TICKET_COUNT_SIZE);
            uint_to_buffer(buffer, &buf_end, e.description_length, DESCRIPTION_LENGTH_SIZE);
            for (uint8_t i = 0; i < e.description_length; i++) {
                buffer[buf_end++] = e.description[i];
            }
            free_space -= event_size;
        }
    }
    return buf_end;
}

size_t build_reservation_message(unsigned char* buffer, reservation_t* r) {
    clear_buffer(buffer);
    buffer[0] = RESERVATION;
    size_t buf_end = 1;

    uint_to_buffer(buffer, &buf_end, r->id, RESERVATION_ID_SIZE);
    uint_to_buffer(buffer, &buf_end, r->event_id, EVENT_ID_SIZE);
    uint_to_buffer(buffer, &buf_end, r->ticket_count, TICKET_COUNT_SIZE);
    for (int i = 0; i < COOKIE_SIZE; i++) {
        buffer[buf_end++] = r->cookie[i];
    }
    uint_to_buffer(buffer, &buf_end, (uint64_t) r->expiration_time, EXPIRATION_TIME_SIZE);
    return buf_end;
}

size_t build_tickets_message(unsigned char* buffer, reservation_t* r, char* ticket_code) {
    clear_buffer(buffer);
    buffer[0] = TICKETS;
    size_t buf_end = 1;

    generate_tickets(r, ticket_code);
    uint_to_buffer(buffer, &buf_end, r->id, RESERVATION_ID_SIZE);
    uint_to_buffer(buffer, &buf_end, r->ticket_count, TICKET_COUNT_SIZE);
    for (int i = 0; i < r->ticket_count; i++) {
        for (int j = 0; j < TICKET_SIZE; j++) {
            buffer[buf_end++] = r->tickets[i].code[j];
        }
    }
    return buf_end;
}

size_t build_bad_request_message(unsigned char* buffer, uint32_t id) {
    clear_buffer(buffer);
    buffer[0] = BAD_REQUEST;
    size_t buf_end = 1;
    uint_to_buffer(buffer, &buf_end, id, EVENT_ID_SIZE);
    return buf_end;
}

// >>> Main <<<
// UDP server working in the endless loop.

int main(int argc, char* argv[]) {
    srand(time(NULL));
    unsigned char buffer[BUF_SIZE];
    char* filename = NULL;
    uint16_t port = 0;
    time_t timeout = 0;
    parse_arguments(argc, argv, &filename, &port, &timeout);

    FILE* file = open_file(filename);
    event_t* events = (event_t*) new_array(1, sizeof(event_t));
    size_t events_count = read_events(file, &events);
    close_file(file, filename);

    reservation_t* reservations = (reservation_t*) new_array(1, sizeof(reservation_t));
    size_t reservations_count = 0;
    size_t reservations_size = 1;
    char ticket_code[TICKET_SIZE + 1];
    strcpy(ticket_code, "0000000");

    int socket_fd = new_socket();
    bind_socket(socket_fd, port);
    struct sockaddr_in client_address;
    size_t read_len;

    do {
        clear_buffer(buffer);
        read_len = read_message(socket_fd, &client_address, buffer, sizeof(buffer));
        time_t rec_time = time(NULL);
        cancel_expired_reservations(reservations, reservations_count, events, events_count);
        uint8_t message_id = get_message_id(buffer, read_len);
        switch (message_id) {
            case GET_EVENTS: {
                if (get_events_length_ok(read_len)) {
                    size_t mess_len = build_events_message(buffer, events, events_count);
                    send_message(socket_fd, &client_address, buffer, mess_len);
                }
                break;
            } case GET_RESERVATION: {
                uint32_t event_id = 0;
                uint16_t ticket_count = 0;
                event_t* event = NULL;

                if (get_reservation_length_ok(read_len)) {
                    if (get_reservation_correct(buffer, &event_id, &ticket_count,
                                                events, events_count, &event)) {
                        reservation_t *reservation = new_reservation(&reservations, &reservations_count, &reservations_size,
                                                                     event_id, ticket_count, rec_time + timeout);
                        change_tickets_available(event, ticket_count, false);
                        size_t mess_len = build_reservation_message(buffer, reservation);
                        send_message(socket_fd, &client_address, buffer, mess_len);
                    } else {
                        size_t mess_len = build_bad_request_message(buffer, event_id);
                        send_message(socket_fd, &client_address, buffer, mess_len);
                    }
                }
                break;
            } case GET_TICKETS: {
                uint32_t reservation_id = 0;
                reservation_t* reservation = NULL;

                if (get_tickets_length_ok(read_len)) {
                    if (get_tickets_correct(buffer, &reservation_id, reservations,
                                            reservations_count, &reservation)) {
                        size_t mess_len = build_tickets_message(buffer, reservation, ticket_code);
                        send_message(socket_fd, &client_address, buffer, mess_len);
                        reservation->sent = true;
                    } else {
                        size_t mess_len = build_bad_request_message(buffer, reservation_id);
                        send_message(socket_fd, &client_address, buffer, mess_len);
                    }
                }
                break;
            }
        }
    } while (true);

    free(events);
    free_tickets(reservations, reservations_count);
    free(reservations);
    close_socket(socket_fd);
    return 0;
}