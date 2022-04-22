
all: clean server client

server: ./src/server.c
	gcc -g -o $@ -Wall $^ -libverbs -lpmem

client : ./src/client.c
	gcc -g -o $@ -Wall $^ -libverbs -lpmem
clean:
	rm -f server

cscope:
	cscope -bqR
