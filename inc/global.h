#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h"
#include <pthread.h>
#include <sys/select.h>
#include <arpa/inet.h>

// 单位是byte
#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

// 一些Flag
#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2
#define TRUE 1
#define FALSE 0

// 定义最大包长 防止IP层分片
#define MAX_DLEN 1375 	// 最大包内数据长度
#define MAX_LEN 1400 	// 最大包长度

// TCP socket 状态定义
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RECV 3
#define ESTABLISHED 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

// RFC 6298 handshake timer defaults. The retry limit is kept in one place so
// it can be adjusted to the value published by the course platform.
#define TJU_INITIAL_RTO_MS 1000
#define TJU_MAX_RTO_MS 60000
#define TJU_SYN_RETRY_LIMIT 3
#define TJU_RTO_AFTER_SYN_RETRANSMIT_MS 3000
#define TJU_FIN_RETRY_LIMIT 3
#define TJU_FIN_INITIAL_RTO_MS 8000
#define TJU_MSL_MS 1000
#define TJU_CLOSE_TIMEOUT_MS 20000

// Reliable transport buffers and timer parameters.
#define TJU_SEND_BUFFER_CAPACITY (5000 * MAX_DLEN)
#define TJU_RECV_BUFFER_CAPACITY (5000 * MAX_DLEN)
#define TJU_REORDER_BUFFER_CAPACITY 65535
#define TJU_MAX_ADVERTISED_WINDOW 65535
#define TJU_DATA_DRAIN_TIMEOUT_MS 120000
#define TJU_CLOCK_GRANULARITY_MS 1
#define TJU_MIN_LOSS_PROBE_MS 10

// TCP 拥塞控制状态
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2

// TCP 接受窗口大小
#define TCP_RECVWN_SIZE 32*MAX_DLEN // 比如最多放32个满载数据包

// TCP 发送窗口
// 注释的内容如果想用就可以用 不想用就删掉 仅仅提供思路和灵感
typedef struct {
	uint16_t window_size;

//   uint32_t base;
//   uint32_t nextseq;
//   uint32_t estmated_rtt;
//   int ack_cnt;
//   pthread_mutex_t ack_cnt_lock;
//   struct timeval send_time;
//   struct timeval timeout;
//   uint16_t rwnd; 
//   int congestion_status;
//   uint16_t cwnd; 
//   uint16_t ssthresh; 
} sender_window_t;

// TCP 接受窗口
// 注释的内容如果想用就可以用 不想用就删掉 仅仅提供思路和灵感
typedef struct {
	char received[TCP_RECVWN_SIZE];

//   received_packet_t* head;
//   char buf[TCP_RECVWN_SIZE];
//   uint8_t marked[TCP_RECVWN_SIZE];
//   uint32_t expect_seq;
} receiver_window_t;

// TCP 窗口 每个建立了连接的TCP都包括发送和接受两个窗口
typedef struct {
	sender_window_t* wnd_send;
  	receiver_window_t* wnd_recv;
} window_t;

typedef struct sent_segment {
    uint32_t seq;
    uint16_t len;
    uint64_t sent_at_us;
    int retransmitted;
    struct sent_segment* next;
} sent_segment_t;

typedef struct {
	uint32_t ip;
	uint16_t port;
} tju_sock_addr;


// TJU_TCP 结构体 保存TJU_TCP用到的各种数据
typedef struct  tju_tcp{
	int state; // TCP的状态

	    // 连接建立需要的序号状态
    uint32_t iss;       // 本端初始发送序号 ISN
    uint32_t irs;       // 对端初始发送序号 ISN
    uint32_t snd_una;   // 最早尚未确认的发送序号
    uint32_t snd_nxt;   // 下一个准备发送的序号
    uint32_t rcv_nxt;   // 下一个期望接收的序号

    int syn_retransmitted;  // 建连阶段SYN是否发生过重传
    int syn_retry_count;    // 本端握手报文已经重传的次数
    uint32_t rto_ms;        // 当前连接使用的重传超时，单位ms

    // 连接关闭状态
    uint32_t fin_seq;       // 本端FIN使用的序号
    int fin_sent;           // 本端是否已经发送FIN
    int fin_acked;          // 本端FIN是否已经得到确认
    int fin_retry_count;    // FIN已经重传的次数
    uint32_t fin_rto_ms;    // FIN独立重传计时器，避免与数据RTO相互覆盖
    int peer_fin_received;  // 是否已经收到并确认对端FIN
    int close_requested;    // 调用close后禁止继续提交发送数据
    int close_failed;       // 关闭是否因超过重试上限失败
    
    // 连接状态变化的同步
    pthread_mutex_t state_lock;
    pthread_cond_t state_cond;

        // accept完成连接队列
    struct tju_tcp* parent_listen;  // 子连接对应的监听socket
    struct tju_tcp* accept_head;    // 已完成连接队列头
    struct tju_tcp* accept_tail;    // 已完成连接队列尾
    struct tju_tcp* accept_next;    // 子连接在队列中的next指针
    
	tju_sock_addr bind_addr; // 存放bind和listen时该socket绑定的IP和端口
	tju_sock_addr established_local_addr; // 存放建立连接后 本机的 IP和端口
	tju_sock_addr established_remote_addr; // 存放建立连接后 连接对方的 IP和端口

	pthread_mutex_t send_lock; // 发送数据锁
	char* sending_buf; // 发送数据缓存区
	int sending_len; // 发送数据缓存长度
	int sending_head;
	pthread_cond_t send_cond;
	pthread_cond_t send_space_cond;
	pthread_cond_t send_drained_cond;
	uint16_t peer_rwnd;
	uint16_t last_peer_rwnd;
	uint32_t last_ack_seen;
	int duplicate_ack_count;
	int fast_retransmit_pending;
	int fast_recovery;
	uint32_t recovery_seq;
	int data_worker_stop;
	int data_worker_started;
	sent_segment_t* inflight_head;
	sent_segment_t* inflight_tail;
	int rtt_initialized;
	double srtt_ms;
	double rttvar_ms;
	uint64_t data_timer_started_us;
	int loss_probe_sent;
	uint64_t zero_probe_due_us;
	uint32_t zero_probe_rto_ms;

	pthread_mutex_t recv_lock; // 接收数据锁
	char* received_buf; // 接收数据缓存区
	int received_len; // 接收数据缓存长度
	int received_head;
	char* recv_window_data;
	uint8_t* recv_window_mark;
	int recv_window_head;
	int recv_window_marked;
	uint16_t last_advertised_window;

	pthread_cond_t wait_cond; // 可以被用来唤醒recv函数调用时等待的线程

	window_t window; // 发送和接受窗口

} tju_tcp_t;

#endif
