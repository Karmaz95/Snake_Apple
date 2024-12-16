CC = clang
FRAMEWORK = -framework Foundation

all: client server

client: client.m
	$(CC) $(FRAMEWORK) client.m -o client

server: server.m
	$(CC) $(FRAMEWORK) server.m -o server

clean:
	rm -f client server *.o

.PHONY: all clean