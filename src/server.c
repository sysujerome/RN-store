#include "rdma.h"

// #define MAX_POLL_CQ_TIMEOUT 2000 // ms
// #define MSG_SIZE 100
// #define MSG "hello RDMA!"


#define MAX_POLL_CQ_TIMEOUT 2000 // ms
#define MSG "This is alice, how are you?"
#define RDMAMSGR "RDMA read operation"
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE (strlen(MSG) + 20)
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









