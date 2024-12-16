CC = clang
CFLAGS = -framework Foundation

all: client server

client: client.m
	$(CC) $(CFLAGS) client.m -o client

server: server.m
	$(CC) $(CFLAGS) server.m -o server

clean:
	rm -f client server *.o

.PHONY: all clean