
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
#include <libpmem.h>

// #define MAX_POLL_CQ_TIMEOUT 2000 // ms
// #define MSG_SIZE 100
// #define MSG "hello RDMA!"


#define MAX_POLL_CQ_TIMEOUT 2000 // ms
#define MSG "This is alice, how are you?"
#define RDMAMSGR "RDMA read operation"
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE (strlen(MSG) + 20)
#define PM_SIZE 300*1024*1024
#define PM_PATH "/pmem/rdma/serverDB"



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
    int pmem_size;
    int is_pmem;

    int sock;
};


// 连接套接字, 客户端和服务器之间通过TCP/IP协议栈来实现彼此的RDMA相关通信信息, 
// 再通过RDMA相关操作来实现通信
int sock_connect(const char *server_name, int port);


//同步阻塞性函数, 将远程的数据和本地的数据进行同步
int sock_sync_data(int sockfd, int xfer_size, char* local_data, char* remote_data);


int poll_completion(struct resource *res);

int post_send(struct resource *res, int opcode);
    
    
    
                
int post_receive(struct resource *res);

void resource_init(struct resource *res);

// 创建服务器端的相关资源, 主要是注册内存和建立QP(Queue Pair)
int resource_create(struct resource *res, struct config_t *config);

int modify_qp_to_init(struct ibv_qp *qp, struct config_t *config);

int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid, struct config_t *config);

int modify_qp_to_rts(struct ibv_qp *qp);

int connect_qp(struct resource *res, struct config_t *config);

int resource_destroy(struct resource *res);


void print_usage(const char *progname);

void print_config(struct config_t *config);