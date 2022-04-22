#include "rdma.h"

// #define MAX_POLL_CQ_TIMEOUT 2000 // ms
// #define MSG_SIZE 100
// #define MSG "hello RDMA!"


#define MAX_POLL_CQ_TIMEOUT 2000 // ms
#define MSG "This is alice, how are you?"
#define RDMAMSGR "RDMA read operation"
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE (strlen(MSG) + 20)
#define PM_PATH "/pmem/rdma/serverDB"
// 300M的内存
#define PM_SIZE 300*1000*1000


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
    // char *buf;
    char *pmemaddr; // pmem映射地址
    size_t pmemsize;
    int is_pmem;

    int sock;
};

// 自身的配置文件
struct config_t config = {.dev_name = NULL,
                          .server_name = NULL,
                          .tcp_port = 20000,
                          .ib_port = 1,
                          .gid_idx = -1};



int main(int argc, char* argv[]) {
    
    struct resource res;

    char temp_char;

    
    print_config(&config);

    resource_init(&res);

    resource_create(&res, &config);

    connect_qp(&res, &config);

    // post_send(&res, IBV_WR_SEND);
    // poll_completion(&res);

    // strcpy(res.buf, RDMAMSGR);
    // strcpy(res.pmemaddr, RDMAMSGR);
    // INFO("消息是: %s\n", res.buf);
    
    // sock_sync_data(res.sock, 1, "R", &temp_char);

    sock_sync_data(res.sock, 1, "W", &temp_char);
    // INFO("服务器的数据是: %s\n", res.pmemaddr);
    // INFO("服务器的数据是: %s\n", res.buf);
    
    resource_destroy(&res);
    return 0;
}









