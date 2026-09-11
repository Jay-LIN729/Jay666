#include "tju_tcp.h"
#include <time.h>
#include <errno.h>

static pthread_mutex_t isn_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t isn_counter = 0;

static uint32_t generate_isn(){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    pthread_mutex_lock(&isn_lock);
    uint32_t cnt = ++isn_counter;
    pthread_mutex_unlock(&isn_lock);

    return (uint32_t)ts.tv_sec ^
           (uint32_t)ts.tv_nsec ^
           (cnt * 2654435761u);
}

static void* synack_retransmit_thread(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;

    while(1){
        struct timespec wait_time;
        wait_time.tv_sec = 1;
        wait_time.tv_nsec = 0;

        nanosleep(&wait_time, NULL);

        pthread_mutex_lock(&(sock->state_lock));

        // 已经收到第三次ACK，或者状态发生变化，则停止重传
        if(sock->state != SYN_RECV){
            pthread_mutex_unlock(&(sock->state_lock));
            break;
        }

        // 仍处于SYN_RECV，重传原来的SYN+ACK
        char* retry_syn_ack = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->iss,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK | ACK_FLAG_MASK,
            65535,
            0,
            NULL,
            0
        );

        sendToLayer3(retry_syn_ack, DEFAULT_HEADER_LEN);
        free(retry_syn_ack);

        pthread_mutex_unlock(&(sock->state_lock));
    }

    return NULL;
}
/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    sock->state = CLOSED;

    // handshake sequence state
    sock->iss = 0;
    sock->irs = 0;
    sock->snd_una = 0;
    sock->snd_nxt = 0;
    sock->rcv_nxt = 0;

    sock->syn_retransmitted = 0;

    // connection state synchronization
    pthread_mutex_init(&(sock->state_lock), NULL);

    if(pthread_cond_init(&(sock->state_cond), NULL) != 0){
        perror("ERROR state condition variable not set\n");
        exit(-1);
    }
   
        sock->parent_listen = NULL;
    sock->accept_head = NULL;
    sock->accept_tail = NULL;
    sock->accept_next = NULL;

    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){

    pthread_mutex_lock(&(listen_sock->state_lock));

    // 已完成连接队列为空时，accept阻塞等待
    while(listen_sock->accept_head == NULL){
        pthread_cond_wait(&(listen_sock->state_cond),
                          &(listen_sock->state_lock));
    }

    // 从已完成连接队列头部取出一个连接
    tju_tcp_t* new_conn = listen_sock->accept_head;
    listen_sock->accept_head = new_conn->accept_next;

    if(listen_sock->accept_head == NULL){
        listen_sock->accept_tail = NULL;
    }

    new_conn->accept_next = NULL;

    pthread_mutex_unlock(&(listen_sock->state_lock));

    return new_conn;
}


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){

    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network(CLIENT_IP);
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;

    // 生成本次连接的初始发送序号
sock->iss = generate_isn();
sock->snd_una = sock->iss;

// SYN会占用一个序号
sock->snd_nxt = sock->iss + 1;

// 客户端进入SYN_SENT状态
sock->state = SYN_SENT;

// 必须先放入已建立连接哈希表
// 这样后续收到SYN+ACK时才能找到这个socket
int hashval = cal_hash(local_addr.ip, local_addr.port,
                       target_addr.ip, target_addr.port);
established_socks[hashval] = sock;

// 构造并发送第一次握手的SYN报文
char* syn_pkt = create_packet_buf(
    sock->established_local_addr.port,
    sock->established_remote_addr.port,
    sock->iss,
    0,
    DEFAULT_HEADER_LEN,
    DEFAULT_HEADER_LEN,
    SYN_FLAG_MASK,
    65535,
    0,
    NULL,
    0
);

sendToLayer3(syn_pkt, DEFAULT_HEADER_LEN);
free(syn_pkt);

// connect必须等到三次握手真正完成后才能返回
pthread_mutex_lock(&(sock->state_lock));

while(sock->state != ESTABLISHED){

    // 当前建连阶段的RTO先设为1秒
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 1;

    int wait_rst = pthread_cond_timedwait(
        &(sock->state_cond),
        &(sock->state_lock),
        &timeout
    );

    // 可能恰好在超时时刻收到了SYN+ACK
    if(sock->state == ESTABLISHED){
        break;
    }

    // 超时仍未建立连接，重传同一个SYN
    if(wait_rst == ETIMEDOUT){

        sock->syn_retransmitted = 1;

        char* retry_syn = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->iss,
            0,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK,
            65535,
            0,
            NULL,
            0
        );

        sendToLayer3(retry_syn, DEFAULT_HEADER_LEN);
        free(retry_syn);
    }
}

pthread_mutex_unlock(&(sock->state_lock));

return 0;
}
int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    // 这里当然不能直接简单地调用sendToLayer3
    char* data = malloc(len);
    memcpy(data, buffer, len);

    char* msg;
    uint32_t seq = 464;
    uint16_t plen = DEFAULT_HEADER_LEN + len;

    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);

    sendToLayer3(msg, plen);
    
    return 0;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    while(sock->received_len<=0){
        // 阻塞
    }

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        char* new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){

        uint8_t flags = get_flags(pkt);

	    // 客户端收到第二次握手 SYN+ACK
    if(sock->state == SYN_SENT &&
       (flags & SYN_FLAG_MASK) &&
       (flags & ACK_FLAG_MASK)){

        uint32_t ack_num = get_ack(pkt);

        // SYN占用一个序号，因此对端应确认 iss + 1
        if(ack_num != sock->snd_nxt){
            return 0;
        }

        // 记录服务器ISN
        sock->irs = get_seq(pkt);
        sock->rcv_nxt = sock->irs + 1;

        // 客户端SYN已被确认
        sock->snd_una = ack_num;

        // 构造第三次握手 ACK
        char* ack_pkt = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->snd_nxt,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK,
            65535,
            0,
            NULL,
            0
        );

        sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
        free(ack_pkt);

        // 三次握手在客户端完成
        pthread_mutex_lock(&(sock->state_lock));
        sock->state = ESTABLISHED;
        pthread_cond_signal(&(sock->state_cond));
        pthread_mutex_unlock(&(sock->state_lock));

        return 0;
    }

        // 客户端已ESTABLISHED后再次收到握手阶段的SYN+ACK
    // 说明第三次ACK可能丢失，需要重新回复ACK
    if(sock->state == ESTABLISHED &&
       (flags & SYN_FLAG_MASK) &&
       (flags & ACK_FLAG_MASK)){

        // 必须确认是本次连接之前的那个SYN+ACK
        if(get_seq(pkt) != sock->irs ||
           get_ack(pkt) != sock->snd_nxt){
            return 0;
        }

        char* retry_ack = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->snd_nxt,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK,
            65535,
            0,
            NULL,
            0
        );

        sendToLayer3(retry_ack, DEFAULT_HEADER_LEN);
        free(retry_ack);

        return 0;
    }

        // SYN_RECV状态下再次收到同一个SYN：
    // 说明客户端可能没有收到之前的SYN+ACK，重新发送SYN+ACK
    if(sock->state == SYN_RECV &&
       (flags & SYN_FLAG_MASK) &&
       !(flags & ACK_FLAG_MASK)){

        // 只接受本次连接原SYN的重传
        if(get_seq(pkt) != sock->irs){
            return 0;
        }

        char* retry_syn_ack = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->iss,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK | ACK_FLAG_MASK,
            65535,
            0,
            NULL,
            0
        );

        sendToLayer3(retry_syn_ack, DEFAULT_HEADER_LEN);
        free(retry_syn_ack);

return 0;
    }

        // 服务器收到第三次握手ACK
    if(sock->state == SYN_RECV &&
       (flags & ACK_FLAG_MASK) &&
       !(flags & SYN_FLAG_MASK)){

        uint32_t ack_num = get_ack(pkt);
        uint32_t seq_num = get_seq(pkt);

        // 必须确认服务器SYN，同时客户端序号也应正确
        if(ack_num != sock->snd_nxt ||
           seq_num != sock->rcv_nxt){
            return 0;
        }

        // 服务器SYN已被确认
        sock->snd_una = ack_num;

        // 连接正式建立
        pthread_mutex_lock(&(sock->state_lock));
        sock->state = ESTABLISHED;
        pthread_cond_signal(&(sock->state_cond));
        pthread_mutex_unlock(&(sock->state_lock));

        // 将完成握手的子连接放入监听socket的accept队列
        tju_tcp_t* listen_sock = sock->parent_listen;

        if(listen_sock != NULL){
            pthread_mutex_lock(&(listen_sock->state_lock));

            sock->accept_next = NULL;

            if(listen_sock->accept_tail == NULL){
                listen_sock->accept_head = sock;
                listen_sock->accept_tail = sock;
            }else{
                listen_sock->accept_tail->accept_next = sock;
                listen_sock->accept_tail = sock;
            }

            // 唤醒正在tju_accept中等待的线程
            pthread_cond_signal(&(listen_sock->state_cond));

            pthread_mutex_unlock(&(listen_sock->state_lock));
        }

        return 0;
    }

    // 监听socket收到第一次握手SYN
    if(sock->state == LISTEN &&
       (flags & SYN_FLAG_MASK) &&
       !(flags & ACK_FLAG_MASK)){

        // 为该连接创建一个新的socket
        tju_tcp_t* new_conn = tju_socket();

        // 设置连接双方地址
        new_conn->established_local_addr = sock->bind_addr;

        new_conn->established_remote_addr.ip = inet_network(CLIENT_IP);
        new_conn->established_remote_addr.port = get_src(pkt);

        // 记录客户端ISN
        new_conn->irs = get_seq(pkt);
        new_conn->rcv_nxt = new_conn->irs + 1;

        // 生成服务器ISN，SYN占用一个序号
        new_conn->iss = generate_isn();
        new_conn->snd_una = new_conn->iss;
        new_conn->snd_nxt = new_conn->iss + 1;

        // 记录该子连接属于哪个监听socket
        new_conn->parent_listen = sock;

        // 进入SYN_RECV状态
        new_conn->state = SYN_RECV;

        // 先放入established_socks
        // 这样客户端第三次ACK到达后能够找到new_conn
        int hashval = cal_hash(
            new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port
        );

        established_socks[hashval] = new_conn;

        // 构造第二次握手 SYN + ACK
        char* syn_ack_pkt = create_packet_buf(
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.port,
            new_conn->iss,
            new_conn->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK | ACK_FLAG_MASK,
            65535,
            0,
            NULL,
            0
        );

        sendToLayer3(syn_ack_pkt, DEFAULT_HEADER_LEN);
free(syn_ack_pkt);

// 启动SYN+ACK超时重传线程
pthread_t synack_thread;
if(pthread_create(&synack_thread,
                  NULL,
                  synack_retransmit_thread,
                  (void*)new_conn) != 0){
    perror("ERROR create SYN+ACK retransmit thread");
    exit(-1);
}

// 后台线程自行结束，不需要join
pthread_detach(synack_thread);

return 0;
    }

    uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

    // 把收到的数据放到接受缓冲区
    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    if(sock->received_buf == NULL){
        sock->received_buf = malloc(data_len);
    }else {
        sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
    }
    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
    sock->received_len += data_len;

    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁


    return 0;
}

int tju_close (tju_tcp_t* sock){
    return 0;
}
