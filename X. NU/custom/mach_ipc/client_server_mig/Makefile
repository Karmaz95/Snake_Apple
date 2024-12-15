# Makefile for Mach IPC example with MIG

# Compiler settings
CC = gcc
CFLAGS = -Wall -Werror

# Default target
all: server client

# Generate MIG files from definition
mig_files: message.defs
	mig message.defs

# Build server with MIG-generated files
server: mig_files server.c messageServer.c
	$(CC) $(CFLAGS) server.c messageServer.c -o server

# Build client with MIG-generated files
client: mig_files client.c messageUser.c
	$(CC) $(CFLAGS) client.c messageUser.c -o client

# Clean generated files and executables
clean:
	rm -f server client message.h messageUser.c messageServer.c

.PHONY: all clean mig_files
