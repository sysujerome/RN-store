
#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


// #define MAX_POLL_CQ_TIMEOUT 2000 // ms
// #define MSG_SIZE 100
// #define MSG "hello RDMA!"


#define MAX_POLL_CQ_TIMEOUT 2000 // ms
#define MSG "This is alice, how are you?"
#define RDMAMSGR "RDMA read operation"
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE (strlen(MSG) + 20)
#define SERVER_COUNT 2

#define ERROR(fmt, args...)                                                    \
    { fprintf(stderr, "ERROR: %s(): " fmt, __func__, ##args); }

#define CHECK(expr)                                                            \
    {                                                                          \
        int rc = (expr);                                                       \
        if (rc != 0) {                                                         \
            perror(strerror(errno));                                           \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    }

#define INFO(fmt, args...)                                                     \
    { printf("INFO: %s(): " fmt, __func__, ##args); }


#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

// structure to exchange data which is needed to connect the QPs
// 连接QP时, 需要交换的数据
struct cm_con_data_t {
    uint64_t addr;   // buffer address
    uint32_t rkey;   // remote key
    uint32_t qp_num; // QP number
    uint16_t lid;    // LID of the IB port
    uint8_t gid[16]; // GID
} __attribute__((packed));

// 测试相关参数的数据结构
struct config_t {
    const char *dev_name; // IB device name
    char *server_name;    // server hostname
    uint32_t tcp_port;    // server TCP port
    int ib_port;          // local IB port to work with
    int gid_idx;          // GID index to use
};

// 本进程的相关资源
struct resource
{
    struct ibv_device_attr device_attr;
    struct ibv_port_attr port_attr;
    struct cm_con_data_t remote_props;
    struct ibv_context *ib_ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr;
    char *buf;

    int sock;
};

// 自身的配置文件
struct config_t configs[SERVER_COUNT];
// configs.dev_name = NULL;
                        //   .server_name = NULL,
                        //   .tcp_port = 20000,
                        //   .ib_port = 1,
                        //   .gid_idx = -1};

// 连接套接字, 客户端和服务器之间通过TCP/IP协议栈来实现彼此的RDMA相关通信信息, 
// 再通过RDMA相关操作来实现通信
static int sock_connect(const char *server_name, int port) {
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;

    struct addrinfo hints = {.ai_flags = AI_PASSIVE,
                             .ai_family = AF_INET,
                             .ai_socktype = SOCK_STREAM};

    sprintf(service, "%d", port);
    // 调用DNS服务来获取地址, hints是期待返回的类型, resolved_addr是返回的结果
    CHECK(getaddrinfo(server_name, service, &hints, &resolved_addr));

    for (iterator = resolved_addr; iterator != NULL; iterator = iterator->ai_next) {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
        assert(sockfd >= 0);

        // 客户端
        CHECK(connect(sockfd, iterator->ai_addr, iterator->ai_addrlen));
        
    }

    return sockfd;
}


//同步阻塞性函数, 将远程的数据和本地的数据进行同步
int sock_sync_data(int sockfd, int xfer_size, char* local_data, char* remote_data) {
    int read_bytes = 0;
    int write_bytes = 0;

    write_bytes = write(sockfd, local_data, xfer_size);
    assert(write_bytes == xfer_size);

    read_bytes = read(sockfd, remote_data, xfer_size);
    assert(read_bytes == xfer_size);

    INFO("同步服务器和客户端的数据, 先将服务器的数据写过去, 再读取客户端的数据\n\n");

    return 0;
}

static int poll_completion(struct resource *res) {
    struct ibv_wc wc;
    unsigned long start_time_ms;
    unsigned long curr_time_ms;
    struct timeval curr_time;
    int poll_result;

    gettimeofday(&curr_time, NULL);
    start_time_ms = (curr_time.tv_sec * 1000) + (curr_time.tv_usec) / 1000;
    do {
        poll_result = ibv_poll_cq(res->cq, 1, &wc);
        gettimeofday(&curr_time, NULL);
        curr_time_ms = curr_time.tv_sec * 1000 + curr_time.tv_usec / 1000;
    } while ((poll_result == 0) && ((curr_time_ms-start_time_ms) < MAX_POLL_CQ_TIMEOUT));

    if (poll_result < 0) {
        ERROR("poll CQ failed.\n");
        goto die;
    } else if (poll_result == 0) {
        ERROR("Completion wasn't found in the CQ after timeout\n");
        goto die;
    } else {
        // INFO("Completion was found in CQ with status 0x%x\n", wc.status);
    }

    if (wc.status != IBV_WC_SUCCESS) {
        ERROR("Got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",wc.status, wc.vendor_err);
        goto die;
    }

    return 0;

die:
    exit(EXIT_FAILURE);

}

static int post_send(struct resource *res, int opcode) {
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    bzero(&sge, sizeof(sge));

    sge.addr = (uintptr_t)res->buf;
    sge.length = MSG_SIZE;
    sge.lkey = res->mr->lkey;

    // 准备发送请求 send work request 
    bzero(&sr, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = opcode;
    sr.send_flags = IBV_EXP_SEND_SIGNALED;

    if (opcode != IBV_WR_SEND) {
        sr.wr.rdma.remote_addr = res->remote_props.addr;
        sr.wr.rdma.rkey = res->remote_props.rkey;
    }

    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));

    switch (opcode)
    {
    case IBV_WR_SEND:
        /* code */
        INFO("Send request was posted\n");
        break;
    case IBV_WR_RDMA_READ:
        INFO("RDME read request was posted\n");
        break;
    case IBV_WR_RDMA_WRITE:
        INFO("RDMA write request was posted\n");
        break;
    default:
        INFO("Unknown request was posted\n");
        break;
    }

    return 0;
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


        // CHECK(ibv_post_send(resources[server_id].qp, &sr, &bad_wr));
        server_addr_gap[server_id] += len;
        
        // poll_completion(&resources[server_id]);
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


static int post_receive(struct resource *res) {
    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;

    bzero(&sge, sizeof(sge));
    sge.addr = (uintptr_t)res->buf;
    sge.length = MSG_SIZE;
    sge.lkey = res->mr->lkey;

    bzero(&rr, sizeof(rr));
    rr.next = NULL;
    rr.wr_id = 0;
    rr.sg_list = &sge;
    rr.num_sge = 1;

    CHECK(ibv_post_recv(res->qp, &rr, &bad_wr));
    INFO("Recieve request was posted\n");

    return 0;
}

static void resource_init(struct resource *res) {
    bzero(res, sizeof(*res));
    res->sock = -1;
}

// 创建服务器端的相关资源, 主要是注册内存和建立QP(Queue Pair)
static int resource_create(struct resource *res, struct config_t *config) {
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;

    size_t size;
    int i;
    int mr_flags = 0;
    int cq_size = 0;
    int num_devices;

    // 客户端连接指定的端口
    res->sock = sock_connect(config->server_name, config->tcp_port);
    if (res->sock < 0) {
        ERROR("Failed to establish TCP connection to server %s, port %d\n",
                                            config->server_name, config->tcp_port);
        goto die;
    }

    INFO("TCP建立成功\n")
    INFO("开始在本地寻找IB设备...\n")

    dev_list = ibv_get_device_list(&num_devices);
    assert(dev_list != NULL);

    if (num_devices == 0) {
        ERROR("找不到IB设备, 当前设备数为%d\n", num_devices);
        goto die;
    }

    INFO("当前IB设备数量为%d\n", num_devices);

    for (i = 0; i < num_devices; ++i) {
        if (!config->dev_name) {
            // strnup函数为: 先申请内存, 再拷贝字符串
            config->dev_name = strdup(ibv_get_device_name(dev_list[i]));
            INFO("服务器的设备未定义, 默认使用第一个设备: %s\n", config->dev_name);
        }

        if (strcmp(ibv_get_device_name(dev_list[i]), config->dev_name) == 0) {
            ib_dev = dev_list[i];   // 确定设备
            break;
        }
    }

    if (!ib_dev) {
        ERROR("IB设备 %s 找不到", config->dev_name);
        goto die;
    }

    res->ib_ctx = ibv_open_device(ib_dev);
    assert(res->ib_ctx != NULL);

    CHECK(ibv_query_port(res->ib_ctx, config->ib_port, &res->port_attr));

    res->pd = ibv_alloc_pd(res->ib_ctx);
    assert(res->pd != NULL);

    cq_size = 1;
    res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
    assert(res->cq != NULL);

    size = 256*1024+30;
    res->buf = (char*)calloc(1, size);
    assert(res->buf != NULL);


    mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    res->mr = ibv_reg_mr(res->pd, res->buf, size, mr_flags);
    assert(res->mr != NULL);

    INFO("MR已经注册, 地址为%p, local key为: %x, remote key为: 0x%x, flags为: 0x%x\n",
                            res->buf, res->mr->lkey, res->mr->rkey, mr_flags);
    
    bzero(&qp_init_attr, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = res->cq;
    qp_init_attr.recv_cq = res->cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    res->qp = ibv_create_qp(res->pd, &qp_init_attr);
    assert(res->qp != NULL);

    INFO("QP已经建立, QP number是%d", res->qp->qp_num);

    return 0;

die:
    exit(EXIT_FAILURE);

}

static int modify_qp_to_init(struct ibv_qp *qp, struct config_t *config) {
    struct ibv_qp_attr attr;
    int flags;

    bzero(&attr, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = config->ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    
    flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    CHECK(ibv_modify_qp(qp, &attr, flags));
    INFO("完成将该QP修改成初始值");

    return 0;
}

static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid, struct config_t *config) {
    struct ibv_qp_attr attr;
    int flags;

    bzero(&attr, sizeof(attr));

    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = config->ib_port;

    if (config->gid_idx >= 0) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = config->gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_EXP_QP_MIN_RNR_TIMER;
    
    CHECK(ibv_modify_qp(qp, &attr, flags));

    INFO("修改QP完成.\n");

    return 0;
}

static int modify_qp_to_rts(struct ibv_qp *qp) {
    struct ibv_qp_attr attr;
    int flags;

    bzero(&attr, sizeof(attr));

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout =0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    CHECK(ibv_modify_qp(qp, &attr, flags));
    return 0;
}

static int connect_qp(struct resource *res, struct config_t *config) {
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    char temp_char;
    union ibv_gid my_gid;

    bzero(&my_gid, sizeof(my_gid));

    if (config->gid_idx >= 0) {
        CHECK(ibv_query_gid(res->ib_ctx, config->ib_port, config->gid_idx, &my_gid));
    }
    local_con_data.addr = htonll((uintptr_t)res->buf);
    local_con_data.rkey = htonl(res->mr->rkey);
    local_con_data.qp_num = htonl(res->qp->qp_num);
    local_con_data.lid = htons(res->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);

    INFO("\n\tLocal LID\t\t=0x%x\n", res->port_attr.lid);

    sock_sync_data(res->sock, sizeof(struct cm_con_data_t), (char*)&local_con_data, (char*)&tmp_con_data);

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    res->remote_props = remote_con_data;
    
    INFO("Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
    INFO("Remote rkey = 0x%x\n", remote_con_data.rkey);
    INFO("Remote QP number = 0x%x\n", remote_con_data.qp_num);
    INFO("Remote LID = 0x%x\n", remote_con_data.lid);

    if (config->gid_idx >= 0) {
        uint8_t *p = remote_con_data.gid;
        int i;
        printf("Remote GID = ");
        for (i = 0; i < 15; ++i) {
            printf("%02x:", p[i]);
        }
        printf("%02x\n", p[15]);
    }
    modify_qp_to_init(res->qp, config);

    // 客户端特有的步骤
    post_receive(res);

    modify_qp_to_rtr(res->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid, config);
    modify_qp_to_rts(res->qp);

    sock_sync_data(res->sock, 1, "Q", &temp_char);
    return 0;
}

static int resource_destroy(struct resource *res) {
    ibv_destroy_qp(res->qp);
    ibv_dereg_mr(res->mr);
    free(res->buf);
    ibv_destroy_cq(res->cq);
    ibv_dealloc_pd(res->pd);
    ibv_close_device(res->ib_ctx);
    close(res->sock);

    return 0;
}


static void print_usage(const char *progname) {
    printf("Usage:\n");
    printf("%s          start a server and wait for connection\n", progname);
    printf("%s <host>   connect to server at <host>\n\n", progname);
    printf("Options:\n");
    printf("-p, --port <port>           listen on / connect to port <port> "
           "(default 20000)\n");
    printf("-d, --ib-dev <dev>          use IB device <dev> (default first "
           "device found)\n");
    printf("-i, --ib-port <port>        use port <port> of IB device (default "
           "1)\n");
    printf("-g, --gid_idx <gid index>   gid index to be used in GRH (default "
           "not used)\n");
    printf("-h, --help                  this message\n");
}

static void print_config(struct config_t *config) {
    {
        INFO("Device name:          %s\n", config->dev_name);
        INFO("IB port:              %u\n", config->ib_port);
    }
    if (config->server_name) {
        INFO("IP:                   %s\n", config->server_name);
    }
    { INFO("TCP port:             %u\n", config->tcp_port); }
    if (config->gid_idx >= 0) {
        INFO("GID index:            %u\n", config->gid_idx);
    }
}

int main(int argc, char* argv[]) {
    
    // // 打开设备, 获取设备相关信息
    // struct ibv_device **dev_list = NULL;
    // int num_devices;
    // dev_list = ibv_get_device_list(&num_devices);
    // printf("%s\n", ibv_get_device_name(dev_list[0]));
    // printf("%d\n", num_devices);
    // struct ibv_device *ib_dev = NULL;
    // ib_dev = dev_list[0];
    // struct ibv_context* ibv_ctx = ibv_open_device(ib_dev);
    // assert(ibv_ctx != NULL);
    // int ibv_port = 1;
    // struct ibv_port_attr port_attr;
    // CHECK(ibv_query_port(ibv_ctx, ibv_port, &port_attr));

    // // 定义protection domain, 即与注册内存相关的参数
    // struct ibv_pd *pd = ibv_alloc_pd(ibv_ctx);
    // assert(pd != NULL);

    // // 创建Completion Queue, 即完成队列, 包括发送和接收队列
    // int cq_size = 1;
    // struct ibv_cq* cq = ibv_create_cq(ibv_ctx, cq_size, NULL, NULL, 0);
    // assert(cq != NULL);

    // // 定义内存数据
    // int size = 13;
    // const char* massage = "hello world!";
    // char* buf = (char*)calloc(1, size);
    // assert(buf != NULL);
    // strcpy(buf, massage);

    // // 注册内存, MR (Memory Region): 已经注册好的内存区域, 网卡可以直接访问
    // int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    // struct ibv_mr* mr = ibv_reg_mr(pd, buf, size, mr_flags);
    // assert(mr != NULL);
    // // 一开始的lkey和mkey都是相同的, 都是本地的key
    // INFO("MR was registered with addr=%p, lkey= 0x%x, rkey= 0x%x, flags= 0x%x\n",
    //     buf, mr->lkey, mr->rkey, mr_flags);

    // // 开始创建Queue Pair (QP), 双端队列, 即两个进程之间的通信队列
    // struct ibv_qp_init_attr qp_init_attr;
    // memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    // qp_init_attr.qp_type = IBV_QPT_RC;
    // qp_init_attr.sq_sig_all = 1;
    // qp_init_attr.send_cq = cq;
    // qp_init_attr.recv_cq = cq;
    // qp_init_attr.cap.max_send_wr = 1;
    // qp_init_attr.cap.max_recv_wr = 1;
    // qp_init_attr.cap.max_send_sge = 1;
    // qp_init_attr.cap.max_recv_sge = 1;

    // // 创建qp
    // struct ibv_qp* qp = ibv_create_qp(pd, &qp_init_attr);
    // assert(qp != NULL);
    // INFO("QP was created, QP number= 0x%x\n", qp->qp_num);


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

    // while (1) {
    //     int c;
    //     static struct option long_options[] = {
    //         {"port", required_argument, 0, 'p'},
    //         {"ib_dev", required_argument, 0, 'd'},
    //         {"ib_port", required_argument, 0, 'i'},
    //         {"gid_idx", required_argument, 0, 'g'},
    //         {"help", no_argument, 0, 'h'},
    //         {NULL, 0, 0, 0}
    //     };

    //     c = getopt_long(argc, argv, "p:d:i:g:h", long_options, NULL);
    //     if (c == -1) break;

    //     switch (c)
    //     {
    //     case 'p':
    //         config->tcp_port = strtoul(optarg, NULL, 0);
    //         break;
    //     case 'd':
    //         config->dev_name = strdup(optarg);
    //         break;
    //     case 'i':
    //         config->ib_port = strtoul(optarg, NULL, 0);
    //         if (config->ib_port < 0) {
    //             print_usage(argv[0]);
    //             exit(EXIT_FAILURE);
    //         }
    //         break;
    //     case 'g':
    //         config->gid_idx = strtoul(optarg, NULL, 0);
    //         if (config->gid_idx < 0) {
    //             print_usage(argv[0]);
    //             exit(EXIT_FAILURE);
    //         }
    //         break;
    //     case 'h':
    //     default:
    //         print_usage(argv[0]);
    //         break;
    //     }
    // }

    // if (optind == argc - 1) {
    //     config->server_name = argv[optind];
    // } else if (optind < argc) {
    //     print_usage(argv[0]);
    //     exit(EXIT_FAILURE);
    // }
    
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
    
    resource_destroy(&resources[1]);
    return 0;
}









