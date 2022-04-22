#include "rdma.h"


// #define MAX_POLL_CQ_TIMEOUT 2000 // ms
// #define MSG_SIZE 100
// #define MSG "hello RDMA!"

#define SERVER_COUNT 2

#define CHECK(expr)                                                            \
    {                                                                          \
        int rc = (expr);                                                       \
        if (rc != 0) {                                                         \
            perror(strerror(errno));                                           \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    }


static int load_data(struct resource *resources) {
    // 用RDMA write技术来完成数据的写入

    const char* data_path = "/home/pjl/benchmark/workloads_500w/workloada-load-5000000.log.formated";
    // char *data_file = "workloada-load-5000000.log.formated";
    FILE *fp = fopen(data_path, "r");
    if (fp == NULL) exit(EXIT_FAILURE);

    char line[256];
    // char key[256];
    size_t len = 0;
    size_t total_len = 0;
    int i = 0, j = 0, count = 0, number = 0;
    clock_t start, end;
    double cpu_time_used;
    
    
    // printf()

    char **keys;
    const int key_count = 5000000;
    keys = (char**)malloc(key_count * sizeof(char*));
    int server_addr_gap[SERVER_COUNT];
    for (int i = 0; i < SERVER_COUNT; i++) {
        server_addr_gap[i] = 0;
    }


    while (fgets(line, sizeof(line), fp)) {
        // size_t len = 0;
        keys[count] = (char*)malloc(30);
        for (i = 0; i < strlen(line)-1; i++) { 
            if (line[i] == ' ') {
                j = 0;
                continue;
            }
            if (line[i] == '\n') break;
            keys[count][j++] = line[i];
        }
        keys[count][j] = '\0';
        count++;
        if (count >= 5000000) break;
    }
    count = 0;
    start = clock();

    int buf_index = 0;
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    for (i = 0; i < 5000000; i++) {
        len = strlen(keys[i])+1;
        keys[i][len-1] = '\t';

        // 确定存储的节点
        int server_id = crc_16(keys[i], len-1) % SERVER_COUNT;

        strncpy(resources[server_id].buf, keys[i], len);
        count++;
        if (count % 1000000 == 0) {
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("%d keys used %f seconds\n", count, cpu_time_used);
        }
        
        // res->buf[buf_index++] = '\0';
        // printf("write %d bits to server.\n%s\n", buf_index, res->buf);

        bzero(&sge, sizeof(sge));

        sge.addr = (uintptr_t)resources[server_id].buf;
        sge.length = len;
        sge.lkey = resources[server_id].mr->lkey;

        // 准备发送请求 send work request 
        bzero(&sr, sizeof(sr));
        sr.next = NULL;
        sr.wr_id = 0;
        sr.sg_list = &sge;
        sr.num_sge = 1;
        sr.opcode = IBV_WR_RDMA_WRITE;
        sr.send_flags = IBV_EXP_SEND_SIGNALED;

        sr.wr.rdma.remote_addr = resources[server_id].remote_props.addr+server_addr_gap[server_id];
        sr.wr.rdma.rkey = resources[server_id].remote_props.rkey;


        CHECK(ibv_post_send(resources[server_id].qp, &sr, &bad_wr));
        server_addr_gap[server_id] += len;
        
        poll_completion(&resources[server_id]);
    }

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("%d keys used %f seconds\n", count, cpu_time_used);
    
    // if (key) free(key);
    for (i = 0 ; i < key_count; i++) {
        free(keys[i]);
    }
    free(keys);
    fclose(fp);
    return 0;
}

int main(int argc, char* argv[]) {
    
    
    struct config_t configs[SERVER_COUNT];

    configs[0].dev_name = NULL;
    configs[0].server_name = "28.10.10.5";
    configs[0].tcp_port = 20000;
    configs[0].ib_port = 1;
    configs[0].gid_idx = -1;

    configs[1].dev_name = NULL;
    configs[1].server_name = "28.10.10.12";
    configs[1].tcp_port = 20000;
    configs[1].ib_port = 1;
    configs[1].gid_idx = -1;



    char temp_char;



    
    // print_config(&configs[1]);
    struct resource resources[SERVER_COUNT];

    for (int i = 0; i < SERVER_COUNT; i++) {
        
        
        resource_init(&resources[i]);

        resource_create(&resources[i], &configs[i]);

        connect_qp(&resources[i], &configs[i]);
    }

    // poll_completion(&res);
    // INFO("消息是: %s\n", res.buf);

    // sock_sync_data(res.sock, 1, "W", &temp_char);

    // post_send(&res, IBV_WR_RDMA_READ);
    // poll_completion(&res);
    // INFO("Contents of server's buffer: %s\n", res.buf);
    // // now we replace what's in the server's buffer
    // strcpy(res.buf, RDMAMSGW);
    // INFO("Now replacing it with: %s\n", res.buf);
    // // post_send(&res, IBV_WR_RDMA_WRITE);

    load_data(resources);

    sock_sync_data(resources[0].sock, 1, "W", &temp_char);
    sock_sync_data(resources[1].sock, 1, "W", &temp_char);
    // INFO("服务器的数据是: %s\n", res.buf);
    
    for (int i = 0; i < SERVER_COUNT; i++) resource_destroy(&resources[i]);
    return 0;
}









