CC=clang
FRAMEWORKS=-framework Foundation

all: server client

server: server.m
	$(CC) $(FRAMEWORKS) server.m -o server

client: client.m
	$(CC) $(FRAMEWORKS) client.m -o client

clean:
	rm -f server client