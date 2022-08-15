# SiK-tickets

Computer Networks - 4. semester @ MIMUW

## Task

Exact task in Polish is in `tresc.pdf` file.

## How to run

```
gcc -Wall -Wextra -Wno-implicit-fallthrough -std=c17 -O2 -o ticket_server ticket_server.c
./ticket_server -f <file> (-p <port> -t <timeout>)
```
