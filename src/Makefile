
all: clean server client

server: server.c
	gcc -g -o $@ -Wall $^ -libverbs -lpmem

client : client.c
	gcc -g -o $@ -Wall $^ -libverbs -lpmem
clean:
	rm -f server

cscope:
	cscope -bqR
