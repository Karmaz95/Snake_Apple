# Makefile for Mach IPC example without MIG

# Compiler settings
CC = gcc
CFLAGS = -Wall -Werror

# Default target
all: server client

# Build server
server: server.c
	$(CC) $(CFLAGS) server.c -o server

# Build client
client: client.c
	$(CC) $(CFLAGS) client.c -o client

# Clean generated files and executables
clean:
	rm -f server client

.PHONY: all clean
