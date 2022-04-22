
all: clean server client

GLAGS = -g -Wall -std=gnu99

server: ./src/server.c
	gcc -o $@ $(GLAGS)  $^ -libverbs -lpmem

client : ./src/client.c ./src/crc16.c
	gcc -o $@ $(GLAGS)  $^ -libverbs -lpmem
clean:
	rm -f server

cscope:
	cscope -bqR
