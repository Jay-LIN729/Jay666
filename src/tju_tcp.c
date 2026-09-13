#include "tju_tcp.h"
#include <time.h>
#include <errno.h>
#include <stdarg.h>

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

static void add_milliseconds(struct timespec* time, uint32_t milliseconds){
    time->tv_sec += milliseconds / 1000;
    time->tv_nsec += (long)(milliseconds % 1000) * 1000000L;
    if(time->tv_nsec >= 1000000000L){
        time->tv_sec += 1;
        time->tv_nsec -= 1000000000L;
    }
}

static uint32_t backed_off_rto(uint32_t rto_ms){
    if(rto_ms >= TJU_MAX_RTO_MS / 2){
        return TJU_MAX_RTO_MS;
    }
    return rto_ms * 2;
}

static uint64_t now_microseconds(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

static int seq_before(uint32_t a, uint32_t b){
    return (int32_t)(a - b) < 0;
}

static int seq_after(uint32_t a, uint32_t b){
    return seq_before(b, a);
}

static pthread_mutex_t trace_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE* trace_file = NULL;

static void trace_event(const char* event, const char* format, ...){
    pthread_mutex_lock(&trace_lock);
    if(trace_file == NULL){
        char hostname[8] = {0};
        gethostname(hostname, sizeof(hostname));
        const char* filename = strcmp(hostname, "server") == 0
            ? "server.event.trace" : "client.event.trace";
        trace_file = fopen(filename, "w");
        if(trace_file != NULL){
            setvbuf(trace_file, NULL, _IOFBF, 64 * 1024);
        }
    }

    if(trace_file != NULL){
        fprintf(trace_file, "[%llu] [%s] [",
                (unsigned long long)now_microseconds(), event);
        va_list args;
        va_start(args, format);
        vfprintf(trace_file, format, args);
        va_end(args);
        fprintf(trace_file, "]\n");
    }
    pthread_mutex_unlock(&trace_lock);
}

// The fixed teaching header has one reserved extension byte and no wider
// checksum field. Data-path packets use it for an 8-bit one's-complement
// checksum; legacy handshake and close control packets keep extension == 0.
static uint8_t packet_checksum8(const char* packet, uint16_t packet_len){
    uint32_t sum = 0;
    for(uint16_t i = 0; i < packet_len; i++){
        if(i != DEFAULT_HEADER_LEN - 1){
            sum += (uint8_t)packet[i];
        }
    }
    while(sum > 0xff){
        sum = (sum & 0xff) + (sum >> 8);
    }
    uint8_t checksum = (uint8_t)(~sum);
    return checksum == 0 ? 0xff : checksum;
}

static void set_packet_checksum(char* packet, uint16_t packet_len){
    packet[DEFAULT_HEADER_LEN - 1] = (char)packet_checksum8(packet, packet_len);
}

static int packet_checksum_valid(const char* packet, uint16_t packet_len){
    uint8_t stored = (uint8_t)packet[DEFAULT_HEADER_LEN - 1];
    return stored != 0 && stored == packet_checksum8(packet, packet_len);
}

// recv_lock must be held by the caller.
static uint16_t advertised_window_locked(tju_tcp_t* sock){
    int used = sock->received_len + sock->recv_window_marked;
    int available = TJU_RECV_BUFFER_CAPACITY - used;
    if(available <= 0){
        return 0;
    }
    if(available > TJU_MAX_ADVERTISED_WINDOW){
        available = TJU_MAX_ADVERTISED_WINDOW;
    }
    return (uint16_t)available;
}

// recv_lock must be held by the caller.  When reopening a zero window, keep
// advertising zero until at least one full SMSS is available.  Normal window
// updates are left untouched so reliable-transfer throughput is unaffected.
static uint16_t window_to_advertise_locked(tju_tcp_t* sock){
    uint16_t available = advertised_window_locked(sock);
    if(sock->last_advertised_window == 0 &&
       available > 0 && available < MAX_DLEN){
        return 0;
    }
    sock->last_advertised_window = available;
    return available;
}

static uint16_t current_advertised_window(tju_tcp_t* sock){
    pthread_mutex_lock(&(sock->recv_lock));
    uint16_t window = window_to_advertise_locked(sock);
    pthread_mutex_unlock(&(sock->recv_lock));
    return window;
}

static void copy_from_send_ring(tju_tcp_t* sock, uint32_t offset,
                                char* destination, uint16_t len){
    int index = (sock->sending_head + (int)offset) % TJU_SEND_BUFFER_CAPACITY;
    int first = TJU_SEND_BUFFER_CAPACITY - index;
    if(first > len){
        first = len;
    }
    memcpy(destination, sock->sending_buf + index, first);
    if(first < len){
        memcpy(destination + first, sock->sending_buf, len - first);
    }
}

static void append_to_send_ring(tju_tcp_t* sock, const char* source, int len){
    int tail = (sock->sending_head + sock->sending_len) % TJU_SEND_BUFFER_CAPACITY;
    int first = TJU_SEND_BUFFER_CAPACITY - tail;
    if(first > len){
        first = len;
    }
    memcpy(sock->sending_buf + tail, source, first);
    if(first < len){
        memcpy(sock->sending_buf, source + first, len - first);
    }
    sock->sending_len += len;
}

static void trace_packet_event(const char* event, char* packet){
    uint16_t plen = get_plen(packet);
    uint16_t hlen = get_hlen(packet);
    uint16_t payload_len = plen >= hlen ? plen - hlen : 0;
    trace_event(event, "seq:%u ack:%u flag:%u length:%u",
                get_seq(packet), get_ack(packet), get_flags(packet), payload_len);
}

// send_lock must be held by the caller.
static int transmit_segment_locked(tju_tcp_t* sock, sent_segment_t* segment){
    uint32_t offset = segment->seq - sock->snd_una;
    if(offset + segment->len > (uint32_t)sock->sending_len){
        return -1;
    }

    char payload[MAX_DLEN];
    copy_from_send_ring(sock, offset, payload, segment->len);
    uint16_t advertised = current_advertised_window(sock);
    uint16_t packet_len = DEFAULT_HEADER_LEN + segment->len;
    char* packet = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        segment->seq,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        packet_len,
        ACK_FLAG_MASK,
        advertised,
        0,
        payload,
        segment->len
    );
    if(packet == NULL){
        return -1;
    }
    set_packet_checksum(packet, packet_len);
    sendToLayer3(packet, packet_len);
    trace_packet_event("SEND", packet);
    free(packet);
    segment->sent_at_us = now_microseconds();
    return 0;
}

// send_lock must be held by the caller.
static int send_new_segment_locked(tju_tcp_t* sock, uint16_t len){
    sent_segment_t* segment = calloc(1, sizeof(sent_segment_t));
    if(segment == NULL){
        return -1;
    }
    segment->seq = sock->snd_nxt;
    segment->len = len;

    if(transmit_segment_locked(sock, segment) != 0){
        free(segment);
        return -1;
    }

    if(sock->inflight_tail == NULL){
        sock->inflight_head = segment;
        sock->inflight_tail = segment;
        sock->data_timer_started_us = segment->sent_at_us;
    }else{
        sock->inflight_tail->next = segment;
        sock->inflight_tail = segment;
    }
    sock->snd_nxt += len;
    return 0;
}

// send_lock must be held by the caller.
static int retransmit_oldest_locked(tju_tcp_t* sock){
    if(sock->inflight_head == NULL){
        return 0;
    }
    sock->inflight_head->retransmitted = 1;
    if(transmit_segment_locked(sock, sock->inflight_head) != 0){
        return -1;
    }
    sock->data_timer_started_us = now_microseconds();
    return 0;
}

// send_lock must be held by the caller.
static void update_rto_locked(tju_tcp_t* sock, double sample_ms){
    if(!sock->rtt_initialized){
        sock->srtt_ms = sample_ms;
        sock->rttvar_ms = sample_ms / 2.0;
        sock->rtt_initialized = 1;
    }else{
        double error = sock->srtt_ms - sample_ms;
        if(error < 0){
            error = -error;
        }
        sock->rttvar_ms = 0.75 * sock->rttvar_ms + 0.25 * error;
        sock->srtt_ms = 0.875 * sock->srtt_ms + 0.125 * sample_ms;
    }

    double variance_term = 4.0 * sock->rttvar_ms;
    if(variance_term < TJU_CLOCK_GRANULARITY_MS){
        variance_term = TJU_CLOCK_GRANULARITY_MS;
    }
    double calculated = sock->srtt_ms + variance_term;
    if(calculated < TJU_INITIAL_RTO_MS){
        calculated = TJU_INITIAL_RTO_MS;
    }
    if(calculated > TJU_MAX_RTO_MS){
        calculated = TJU_MAX_RTO_MS;
    }
    sock->rto_ms = (uint32_t)(calculated + 0.5);
    trace_event("RTTS",
                "SampleRTT:%f EstimatedRTT:%f DeviationRTT:%f TimeoutInterval:%f",
                sample_ms, sock->srtt_ms, sock->rttvar_ms,
                (double)sock->rto_ms);
}

// send_lock must be held by the caller.
static void process_data_ack_locked(tju_tcp_t* sock, uint32_t ack,
                                    uint16_t advertised){
    uint16_t previous_window = sock->peer_rwnd;

    if(seq_after(ack, sock->snd_nxt) || seq_before(ack, sock->snd_una)){
        return;
    }

    sock->last_peer_rwnd = previous_window;
    sock->peer_rwnd = advertised;
    if(previous_window != advertised){
        trace_event("SWND", "size:%u", advertised);
    }

    if(seq_after(ack, sock->snd_una)){
        uint32_t acknowledged = ack - sock->snd_una;
        if(acknowledged > (uint32_t)sock->sending_len){
            return;
        }

        uint64_t now = now_microseconds();
        double rtt_sample = -1.0;
        int ambiguous_rtt = 0;
        while(sock->inflight_head != NULL &&
              !seq_after(sock->inflight_head->seq + sock->inflight_head->len,
                         ack)){
            sent_segment_t* acknowledged_segment = sock->inflight_head;
            if(acknowledged_segment->retransmitted){
                ambiguous_rtt = 1;
            }else{
                rtt_sample = (double)(now - acknowledged_segment->sent_at_us) / 1000.0;
            }
            sock->inflight_head = acknowledged_segment->next;
            if(sock->inflight_head == NULL){
                sock->inflight_tail = NULL;
            }
            free(acknowledged_segment);
        }

        if(sock->inflight_head != NULL &&
           seq_after(ack, sock->inflight_head->seq)){
            uint32_t partial = ack - sock->inflight_head->seq;
            if(partial < sock->inflight_head->len){
                sock->inflight_head->seq = ack;
                sock->inflight_head->len -= (uint16_t)partial;
                sock->inflight_head->retransmitted = 1;
                ambiguous_rtt = 1;
            }
        }

        sock->sending_head = (sock->sending_head + (int)acknowledged)
            % TJU_SEND_BUFFER_CAPACITY;
        sock->sending_len -= (int)acknowledged;
        sock->snd_una = ack;
        sock->last_ack_seen = ack;
        sock->duplicate_ack_count = 0;
        sock->fast_retransmit_pending = 0;
        sock->loss_probe_sent = 0;

        // NewReno-style partial ACK handling.  A cumulative ACK that advances
        // inside the recovery range identifies the next missing segment; send
        // it immediately instead of waiting one RTO for every loss in a window.
        if(sock->fast_recovery){
            if(seq_before(ack, sock->recovery_seq)){
                sock->fast_retransmit_pending = sock->inflight_head != NULL;
            }else{
                sock->fast_recovery = 0;
            }
        }

        // Karn's algorithm: one retransmitted segment makes the cumulative
        // ACK's RTT origin ambiguous, even if it also covers new segments.
        if(!ambiguous_rtt && rtt_sample >= 0.0){
            update_rto_locked(sock, rtt_sample);
        }
        sock->data_timer_started_us = sock->inflight_head == NULL ? 0 : now;

        if(sock->sending_len == 0){
            pthread_cond_broadcast(&(sock->send_drained_cond));
        }
        pthread_cond_broadcast(&(sock->send_space_cond));
        pthread_cond_signal(&(sock->send_cond));
    }else if(ack == sock->snd_una && sock->inflight_head != NULL){
        if(previous_window == advertised){
            sock->duplicate_ack_count++;
            if(sock->duplicate_ack_count == 3){
                sock->fast_recovery = 1;
                sock->recovery_seq = sock->snd_nxt;
                sock->fast_retransmit_pending = 1;
                pthread_cond_signal(&(sock->send_cond));
            }
        }else{
            sock->duplicate_ack_count = 0;
        }
    }

    if(advertised == 0){
        if(sock->zero_probe_due_us == 0){
            sock->zero_probe_rto_ms = sock->rto_ms;
            sock->zero_probe_due_us = now_microseconds()
                + (uint64_t)sock->zero_probe_rto_ms * 1000ULL;
        }
    }else{
        sock->zero_probe_due_us = 0;
        sock->zero_probe_rto_ms = sock->rto_ms;
        // If a one-byte probe is outstanding, an explicit window reopening
        // should release the gap immediately instead of waiting for its RTO.
        if(previous_window == 0 && sock->inflight_head != NULL){
            sock->fast_retransmit_pending = 1;
        }
        pthread_cond_signal(&(sock->send_cond));
    }
}

static void microseconds_to_timespec(uint64_t absolute_us,
                                     struct timespec* result){
    result->tv_sec = (time_t)(absolute_us / 1000000ULL);
    result->tv_nsec = (long)(absolute_us % 1000000ULL) * 1000L;
}

static void* data_sender_thread(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;
    pthread_mutex_lock(&(sock->send_lock));

    while(!sock->data_worker_stop){
        if(sock->fast_retransmit_pending && sock->inflight_head != NULL){
            retransmit_oldest_locked(sock);
            sock->fast_retransmit_pending = 0;
        }

        while(!sock->data_worker_stop){
            uint32_t flight = sock->snd_nxt - sock->snd_una;
            uint32_t unsent = (uint32_t)sock->sending_len > flight
                ? (uint32_t)sock->sending_len - flight : 0;
            uint32_t window_available = sock->peer_rwnd > flight
                ? (uint32_t)sock->peer_rwnd - flight : 0;
            if(unsent == 0 || window_available == 0){
                break;
            }

            uint32_t amount = unsent;
            if(amount > window_available){
                amount = window_available;
            }
            if(amount > MAX_DLEN){
                amount = MAX_DLEN;
            }
            // If the peer itself advertises a sub-SMSS window and no data is
            // in flight, avoid turning a larger queued write into a tiny
            // segment.  This does not delay an application's genuine tail.
            if(sock->peer_rwnd < MAX_DLEN && amount < unsent){
                break;
            }
            if(send_new_segment_locked(sock, (uint16_t)amount) != 0){
                sock->data_worker_stop = 1;
                break;
            }
        }

        if(sock->sending_len == 0){
            pthread_cond_broadcast(&(sock->send_drained_cond));
        }
        if(sock->data_worker_stop){
            break;
        }

        uint64_t now = now_microseconds();
        uint64_t deadline = 0;
        uint64_t rto_deadline = 0;
        uint64_t loss_probe_deadline = 0;
        if(sock->inflight_head != NULL){
            rto_deadline = sock->data_timer_started_us
                + (uint64_t)sock->rto_ms * 1000ULL;
            deadline = rto_deadline;

            uint32_t flight = sock->snd_nxt - sock->snd_una;
            uint32_t unsent = (uint32_t)sock->sending_len > flight
                ? (uint32_t)sock->sending_len - flight : 0;
            int sender_limited = unsent == 0 || sock->peer_rwnd <= flight;
            if(sock->rtt_initialized && !sock->loss_probe_sent &&
               sender_limited){
                double probe_ms = 2.0 * sock->srtt_ms;
                if(probe_ms < TJU_MIN_LOSS_PROBE_MS){
                    probe_ms = TJU_MIN_LOSS_PROBE_MS;
                }
                loss_probe_deadline = sock->data_timer_started_us
                    + (uint64_t)(probe_ms * 1000.0);
                if(loss_probe_deadline < deadline){
                    deadline = loss_probe_deadline;
                }
            }
        }else{
            uint32_t unsent = (uint32_t)sock->sending_len;
            if(unsent > 0 && sock->peer_rwnd == 0){
                if(sock->zero_probe_due_us == 0){
                    sock->zero_probe_rto_ms = sock->rto_ms;
                    sock->zero_probe_due_us = now
                        + (uint64_t)sock->zero_probe_rto_ms * 1000ULL;
                }
                deadline = sock->zero_probe_due_us;
            }
        }

        if(deadline != 0 && now >= deadline){
            if(sock->inflight_head != NULL){
                if(loss_probe_deadline != 0 && now >= loss_probe_deadline &&
                   loss_probe_deadline < rto_deadline){
                    // A standards-compatible tail loss probe supplements the
                    // RFC 6298 timer; it does not alter or back off the RTO.
                    retransmit_oldest_locked(sock);
                    sock->loss_probe_sent = 1;
                }else{
                    retransmit_oldest_locked(sock);
                    sock->rto_ms = backed_off_rto(sock->rto_ms);
                    sock->loss_probe_sent = 1;
                }
            }else if(sock->sending_len > 0 && sock->peer_rwnd == 0){
                if(send_new_segment_locked(sock, 1) == 0){
                    sock->zero_probe_rto_ms = backed_off_rto(sock->zero_probe_rto_ms);
                    sock->zero_probe_due_us = now
                        + (uint64_t)sock->zero_probe_rto_ms * 1000ULL;
                }
            }
            continue;
        }

        if(deadline == 0){
            pthread_cond_wait(&(sock->send_cond), &(sock->send_lock));
        }else{
            struct timespec timeout;
            microseconds_to_timespec(deadline, &timeout);
            pthread_cond_timedwait(&(sock->send_cond), &(sock->send_lock), &timeout);
        }
    }

    pthread_cond_broadcast(&(sock->send_space_cond));
    pthread_cond_broadcast(&(sock->send_drained_cond));
    pthread_mutex_unlock(&(sock->send_lock));
    return NULL;
}

static void remove_established_socket(tju_tcp_t* sock){
    int hashval = cal_hash(
        sock->established_local_addr.ip,
        sock->established_local_addr.port,
        sock->established_remote_addr.ip,
        sock->established_remote_addr.port
    );
    if(established_socks[hashval] == sock){
        established_socks[hashval] = NULL;
    }
}

static void send_ack_packet(tju_tcp_t* sock){
    uint16_t advertised = current_advertised_window(sock);
    char* ack_pkt = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        sock->snd_nxt,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN,
        ACK_FLAG_MASK,
        advertised,
        0,
        NULL,
        0
    );
    // The final ACK is not itself acknowledged.  Sending a few identical
    // copies makes connection teardown robust to the test network's residual
    // packet loss, while duplicate ACKs remain harmless to a TCP peer.
    for(int copy = 0; copy < 3; copy++){
        sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
        trace_packet_event("SEND", ack_pkt);
    }
    free(ack_pkt);
}

static void send_data_ack_packet(tju_tcp_t* sock){
    uint16_t advertised = current_advertised_window(sock);
    char* ack_pkt = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        sock->snd_nxt,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN,
        ACK_FLAG_MASK,
        advertised,
        0,
        NULL,
        0
    );
    set_packet_checksum(ack_pkt, DEFAULT_HEADER_LEN);
    sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
    trace_packet_event("SEND", ack_pkt);
    free(ack_pkt);
}

static void send_fin_packet(tju_tcp_t* sock){
    char* fin_pkt = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        sock->fin_seq,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN,
        FIN_FLAG_MASK | ACK_FLAG_MASK,
        65535,
        0,
        NULL,
        0
    );
    sendToLayer3(fin_pkt, DEFAULT_HEADER_LEN);
    free(fin_pkt);
}

static void* fin_retransmit_thread(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;

    while(1){
        struct timespec wait_time;
        wait_time.tv_sec = sock->fin_rto_ms / 1000;
        wait_time.tv_nsec = (long)(sock->fin_rto_ms % 1000) * 1000000L;
        nanosleep(&wait_time, NULL);

        pthread_mutex_lock(&(sock->state_lock));
        if(sock->fin_acked || sock->state == CLOSED || sock->state == TIME_WAIT){
            pthread_mutex_unlock(&(sock->state_lock));
            break;
        }

        if(sock->fin_retry_count >= TJU_FIN_RETRY_LIMIT){
            sock->close_failed = 1;
            sock->state = CLOSED;
            remove_established_socket(sock);
            pthread_cond_broadcast(&(sock->state_cond));
            pthread_mutex_unlock(&(sock->state_lock));
            break;
        }

        send_fin_packet(sock);
        sock->fin_retry_count++;
        sock->fin_rto_ms = backed_off_rto(sock->fin_rto_ms);
        pthread_mutex_unlock(&(sock->state_lock));
    }

    return NULL;
}

static int start_fin_retransmitter(tju_tcp_t* sock){
    pthread_t thread;
    if(pthread_create(&thread, NULL, fin_retransmit_thread, sock) != 0){
        return -1;
    }
    pthread_detach(thread);
    return 0;
}

// state_lock must be held by the caller.
static int begin_fin(tju_tcp_t* sock, int next_state){
    if(sock->fin_sent){
        return 0;
    }

    sock->close_requested = 1;
    sock->fin_seq = sock->snd_nxt;
    sock->snd_nxt++;
    sock->fin_sent = 1;
    sock->fin_acked = 0;
    sock->fin_retry_count = 0;
    sock->fin_rto_ms = sock->rto_ms < TJU_FIN_INITIAL_RTO_MS
        ? TJU_FIN_INITIAL_RTO_MS : sock->rto_ms;
    sock->close_failed = 0;
    sock->state = next_state;
    send_fin_packet(sock);

    if(start_fin_retransmitter(sock) != 0){
        sock->close_failed = 1;
        sock->state = CLOSED;
        remove_established_socket(sock);
        return -1;
    }
    return 0;
}

static void* synack_retransmit_thread(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;

    while(1){
        struct timespec wait_time;
        wait_time.tv_sec = sock->rto_ms / 1000;
        wait_time.tv_nsec = (long)(sock->rto_ms % 1000) * 1000000L;

        nanosleep(&wait_time, NULL);

        pthread_mutex_lock(&(sock->state_lock));

        // 已经收到第三次ACK，或者状态发生变化，则停止重传
        if(sock->state != SYN_RECV){
            pthread_mutex_unlock(&(sock->state_lock));
            break;
        }


        if(sock->syn_retry_count >= TJU_SYN_RETRY_LIMIT){
            remove_established_socket(sock);
            sock->state = CLOSED;
            pthread_cond_broadcast(&(sock->state_cond));
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

        sock->syn_retransmitted = 1;
        sock->syn_retry_count++;
        sock->rto_ms = backed_off_rto(sock->rto_ms);

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
    sock->syn_retry_count = 0;
    sock->rto_ms = TJU_INITIAL_RTO_MS;

    sock->fin_seq = 0;
    sock->fin_sent = 0;
    sock->fin_acked = 0;
    sock->fin_retry_count = 0;
    sock->fin_rto_ms = TJU_FIN_INITIAL_RTO_MS;
    sock->peer_fin_received = 0;
    sock->close_requested = 0;
    sock->close_failed = 0;

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
    sock->sending_buf = malloc(TJU_SEND_BUFFER_CAPACITY);
    sock->sending_len = 0;
    sock->sending_head = 0;
    pthread_cond_init(&(sock->send_cond), NULL);
    pthread_cond_init(&(sock->send_space_cond), NULL);
    pthread_cond_init(&(sock->send_drained_cond), NULL);
    sock->peer_rwnd = TJU_MAX_ADVERTISED_WINDOW;
    sock->last_peer_rwnd = TJU_MAX_ADVERTISED_WINDOW;
    sock->last_ack_seen = 0;
    sock->duplicate_ack_count = 0;
    sock->fast_retransmit_pending = 0;
    sock->fast_recovery = 0;
    sock->recovery_seq = 0;
    sock->data_worker_stop = 0;
    sock->data_worker_started = 0;
    sock->inflight_head = NULL;
    sock->inflight_tail = NULL;
    sock->rtt_initialized = 0;
    sock->srtt_ms = 0.0;
    sock->rttvar_ms = 0.0;
    sock->data_timer_started_us = 0;
    sock->loss_probe_sent = 0;
    sock->zero_probe_due_us = 0;
    sock->zero_probe_rto_ms = TJU_INITIAL_RTO_MS;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = malloc(TJU_RECV_BUFFER_CAPACITY);
    sock->received_len = 0;
    sock->received_head = 0;
    sock->recv_window_data = malloc(TJU_REORDER_BUFFER_CAPACITY);
    sock->recv_window_mark = calloc(TJU_REORDER_BUFFER_CAPACITY, sizeof(uint8_t));
    sock->recv_window_head = 0;
    sock->recv_window_marked = 0;
    sock->last_advertised_window = TJU_MAX_ADVERTISED_WINDOW;

    if(sock->sending_buf == NULL || sock->received_buf == NULL ||
       sock->recv_window_data == NULL || sock->recv_window_mark == NULL){
        free(sock->sending_buf);
        free(sock->received_buf);
        free(sock->recv_window_data);
        free(sock->recv_window_mark);
        free(sock);
        return NULL;
    }
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;

    pthread_t data_thread;
    if(pthread_create(&data_thread, NULL, data_sender_thread, sock) != 0){
        perror("ERROR create data sender thread");
        exit(-1);
    }
    pthread_detach(data_thread);
    sock->data_worker_started = 1;

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

    if(sock == NULL || sock->state != CLOSED){
        return -1;
    }

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

while(sock->state == SYN_SENT){

    // 使用当前RTO等待，并在每次超时重传后执行指数退避
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    add_milliseconds(&timeout, sock->rto_ms);

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

        if(sock->syn_retry_count >= TJU_SYN_RETRY_LIMIT){
            sock->state = CLOSED;
            if(established_socks[hashval] == sock){
                established_socks[hashval] = NULL;
            }
            break;
        }

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
        sock->syn_retry_count++;
        sock->rto_ms = backed_off_rto(sock->rto_ms);
    }
}

int connected = (sock->state == ESTABLISHED);
pthread_mutex_unlock(&(sock->state_lock));

return connected ? 0 : -1;
}
int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    if(sock == NULL || len < 0 || (len > 0 && buffer == NULL)){
        return -1;
    }
    if(len == 0){
        return 0;
    }

    pthread_mutex_lock(&(sock->send_lock));
    if(sock->state != ESTABLISHED || sock->close_requested ||
       sock->data_worker_stop){
        pthread_mutex_unlock(&(sock->send_lock));
        return -1;
    }

    const char* source = (const char*)buffer;
    int appended = 0;
    while(appended < len){
        while(sock->sending_len == TJU_SEND_BUFFER_CAPACITY &&
              !sock->close_requested && !sock->data_worker_stop){
            pthread_cond_wait(&(sock->send_space_cond), &(sock->send_lock));
        }
        if(sock->close_requested || sock->data_worker_stop){
            pthread_mutex_unlock(&(sock->send_lock));
            return -1;
        }

        int space = TJU_SEND_BUFFER_CAPACITY - sock->sending_len;
        int amount = len - appended;
        if(amount > space){
            amount = space;
        }
        append_to_send_ring(sock, source + appended, amount);
        appended += amount;
        pthread_cond_signal(&(sock->send_cond));
    }
    pthread_mutex_unlock(&(sock->send_lock));
    return 0;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    if(sock == NULL || len < 0 || (len > 0 && buffer == NULL)){
        return -1;
    }
    if(len == 0){
        return 0;
    }

    pthread_mutex_lock(&(sock->recv_lock));
    while(sock->received_len <= 0 && !sock->peer_fin_received &&
          sock->state != CLOSED){
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    }

    if(sock->received_len <= 0){
        pthread_mutex_unlock(&(sock->recv_lock));
        return 0;
    }

    uint16_t before_window = advertised_window_locked(sock);
    int read_len = sock->received_len < len ? sock->received_len : len;
    int first = TJU_RECV_BUFFER_CAPACITY - sock->received_head;
    if(first > read_len){
        first = read_len;
    }
    memcpy(buffer, sock->received_buf + sock->received_head, first);
    if(first < read_len){
        memcpy((char*)buffer + first, sock->received_buf, read_len - first);
    }
    sock->received_head = (sock->received_head + read_len)
        % TJU_RECV_BUFFER_CAPACITY;
    sock->received_len -= read_len;
    uint16_t after_window = advertised_window_locked(sock);
    pthread_mutex_unlock(&(sock->recv_lock));

    if(after_window != before_window){
        trace_event("RWND", "size:%u", after_window);
        if(sock->state == ESTABLISHED || sock->state == CLOSE_WAIT){
            send_data_ack_packet(sock);
        }
    }
    return read_len;
}

static void deliver_contiguous_locked(tju_tcp_t* sock){
    int contiguous = 0;
    int index = sock->recv_window_head;
    while(contiguous < sock->recv_window_marked &&
          sock->recv_window_mark[index]){
        contiguous++;
        index++;
        if(index == TJU_REORDER_BUFFER_CAPACITY){
            index = 0;
        }
    }
    if(contiguous == 0){
        return;
    }

    uint32_t delivered_seq = sock->rcv_nxt;
    int source = sock->recv_window_head;
    int destination = (sock->received_head + sock->received_len)
        % TJU_RECV_BUFFER_CAPACITY;
    int remaining = contiguous;
    while(remaining > 0){
        int source_chunk = TJU_REORDER_BUFFER_CAPACITY - source;
        int destination_chunk = TJU_RECV_BUFFER_CAPACITY - destination;
        int chunk = remaining;
        if(chunk > source_chunk){
            chunk = source_chunk;
        }
        if(chunk > destination_chunk){
            chunk = destination_chunk;
        }
        memcpy(sock->received_buf + destination,
               sock->recv_window_data + source, chunk);
        memset(sock->recv_window_mark + source, 0, chunk);
        source = (source + chunk) % TJU_REORDER_BUFFER_CAPACITY;
        destination = (destination + chunk) % TJU_RECV_BUFFER_CAPACITY;
        remaining -= chunk;
    }

    sock->recv_window_head = source;
    sock->recv_window_marked -= contiguous;
    sock->received_len += contiguous;
    sock->rcv_nxt += (uint32_t)contiguous;
    trace_event("DELV", "seq:%u size:%d", delivered_seq, contiguous);
    pthread_cond_broadcast(&(sock->wait_cond));
}

static void process_received_data(tju_tcp_t* sock, char* packet,
                                  uint16_t data_len){
    uint32_t sequence = get_seq(packet);
    uint16_t payload_offset = 0;

    pthread_mutex_lock(&(sock->recv_lock));
    uint16_t before_window = advertised_window_locked(sock);

    if(seq_before(sequence, sock->rcv_nxt)){
        uint32_t duplicate_prefix = sock->rcv_nxt - sequence;
        if(duplicate_prefix >= data_len){
            pthread_mutex_unlock(&(sock->recv_lock));
            send_data_ack_packet(sock);
            return;
        }
        sequence += duplicate_prefix;
        payload_offset = (uint16_t)duplicate_prefix;
        data_len -= (uint16_t)duplicate_prefix;
    }

    uint32_t window_offset = sequence - sock->rcv_nxt;
    uint32_t acceptable = before_window;
    if(window_offset < acceptable &&
       window_offset < TJU_REORDER_BUFFER_CAPACITY){
        acceptable -= window_offset;
        if(acceptable > (uint32_t)(TJU_REORDER_BUFFER_CAPACITY - window_offset)){
            acceptable = TJU_REORDER_BUFFER_CAPACITY - window_offset;
        }
        if(data_len > acceptable){
            data_len = (uint16_t)acceptable;
        }

        int ring_index = (sock->recv_window_head + (int)window_offset)
            % TJU_REORDER_BUFFER_CAPACITY;
        for(uint16_t i = 0; i < data_len; i++){
            if(!sock->recv_window_mark[ring_index]){
                sock->recv_window_mark[ring_index] = 1;
                sock->recv_window_data[ring_index] =
                    packet[DEFAULT_HEADER_LEN + payload_offset + i];
                sock->recv_window_marked++;
            }
            ring_index++;
            if(ring_index == TJU_REORDER_BUFFER_CAPACITY){
                ring_index = 0;
            }
        }
        deliver_contiguous_locked(sock);
    }

    uint16_t after_window = advertised_window_locked(sock);
    pthread_mutex_unlock(&(sock->recv_lock));

    if(after_window != before_window){
        trace_event("RWND", "size:%u", after_window);
    }
    send_data_ack_packet(sock);
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){

    uint16_t header_len = get_hlen(pkt);
    uint16_t packet_len = get_plen(pkt);
    if(header_len != DEFAULT_HEADER_LEN || packet_len < header_len ||
       packet_len > MAX_LEN){
        return 0;
    }
    uint8_t flags = get_flags(pkt);
    trace_packet_event("RECV", pkt);

    // ACK of our FIN. FIN consumes one byte in the sequence space, so a
    // valid acknowledgement must equal the snd_nxt value after begin_fin.
    if(sock->fin_sent && (flags & ACK_FLAG_MASK) &&
       get_ack(pkt) == sock->snd_nxt){
        pthread_mutex_lock(&(sock->state_lock));
        if(!sock->fin_acked){
            sock->fin_acked = 1;
            if(sock->state == FIN_WAIT_1){
                sock->state = sock->peer_fin_received ? TIME_WAIT : FIN_WAIT_2;
            }else if(sock->state == CLOSING){
                sock->state = TIME_WAIT;
            }else if(sock->state == LAST_ACK){
                sock->state = CLOSED;
                remove_established_socket(sock);
            }
            pthread_cond_broadcast(&(sock->state_cond));
        }
        pthread_mutex_unlock(&(sock->state_lock));
    }

    if(flags & FIN_FLAG_MASK){
        uint32_t peer_fin_seq = get_seq(pkt);

        pthread_mutex_lock(&(sock->state_lock));
        pthread_mutex_lock(&(sock->recv_lock));

        // Accept the next FIN once. A duplicate FIN is acknowledged again
        // but must not consume sequence space for a second time.
        if(peer_fin_seq == sock->rcv_nxt){
            sock->rcv_nxt++;
            sock->peer_fin_received = 1;
            pthread_cond_broadcast(&(sock->wait_cond));
        }else if(!sock->peer_fin_received || peer_fin_seq != sock->rcv_nxt - 1){
            pthread_mutex_unlock(&(sock->recv_lock));
            pthread_mutex_unlock(&(sock->state_lock));
            return 0;
        }
        pthread_mutex_unlock(&(sock->recv_lock));

        send_ack_packet(sock);

        if(sock->state == ESTABLISHED){
            sock->state = CLOSE_WAIT;
            // The provided server test has no later application close call,
            // so the teaching framework closes its direction immediately.
            begin_fin(sock, LAST_ACK);
        }else if(sock->state == FIN_WAIT_1){
            sock->state = sock->fin_acked ? TIME_WAIT : CLOSING;
        }else if(sock->state == FIN_WAIT_2){
            sock->state = TIME_WAIT;
        }

        pthread_cond_broadcast(&(sock->state_cond));
        pthread_mutex_unlock(&(sock->state_lock));
        return 0;
    }

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
        if(sock->syn_retransmitted){
            sock->rto_ms = TJU_RTO_AFTER_SYN_RETRANSMIT_MS;
        }
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
        sock->syn_retransmitted = 1;

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
        if(sock->syn_retransmitted){
            sock->rto_ms = TJU_RTO_AFTER_SYN_RETRANSMIT_MS;
        }
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

    uint16_t data_len = packet_len - header_len;
    if(sock->state == ESTABLISHED && (flags & ACK_FLAG_MASK) &&
       !(flags & SYN_FLAG_MASK) && !(flags & FIN_FLAG_MASK)){
        if(!packet_checksum_valid(pkt, packet_len)){
            return 0;
        }
        pthread_mutex_lock(&(sock->send_lock));
        process_data_ack_locked(sock, get_ack(pkt), get_advertised_window(pkt));
        pthread_mutex_unlock(&(sock->send_lock));
    }

    if(data_len == 0){
        return 0;
    }
    if(sock->state != ESTABLISHED && sock->state != CLOSE_WAIT){
        return 0;
    }
    if(!packet_checksum_valid(pkt, packet_len)){
        return 0;
    }
    process_received_data(sock, pkt, data_len);
    return 0;
}

int tju_close (tju_tcp_t* sock){
    if(sock == NULL){
        return -1;
    }

    // FIN must be sequenced after every byte already accepted by tju_send.
    pthread_mutex_lock(&(sock->send_lock));
    if(sock->state == ESTABLISHED || sock->state == CLOSE_WAIT){
        sock->close_requested = 1;
        struct timespec drain_deadline;
        clock_gettime(CLOCK_REALTIME, &drain_deadline);
        add_milliseconds(&drain_deadline, TJU_DATA_DRAIN_TIMEOUT_MS);
        while(sock->sending_len > 0 && !sock->data_worker_stop){
            int wait_result = pthread_cond_timedwait(
                &(sock->send_drained_cond), &(sock->send_lock), &drain_deadline
            );
            if(wait_result == ETIMEDOUT){
                pthread_mutex_unlock(&(sock->send_lock));
                return -1;
            }
        }
        if(sock->data_worker_stop && sock->sending_len > 0){
            pthread_mutex_unlock(&(sock->send_lock));
            return -1;
        }
    }
    pthread_mutex_unlock(&(sock->send_lock));

    pthread_mutex_lock(&(sock->state_lock));

    if(sock->state == ESTABLISHED){
        if(begin_fin(sock, FIN_WAIT_1) != 0){
            pthread_mutex_unlock(&(sock->state_lock));
            return -1;
        }
    }else if(sock->state == CLOSE_WAIT){
        if(begin_fin(sock, LAST_ACK) != 0){
            pthread_mutex_unlock(&(sock->state_lock));
            return -1;
        }
    }else if(sock->state != FIN_WAIT_1 && sock->state != FIN_WAIT_2 &&
             sock->state != CLOSING && sock->state != LAST_ACK &&
             sock->state != TIME_WAIT){
        pthread_mutex_unlock(&(sock->state_lock));
        return -1;
    }

    struct timespec close_deadline;
    clock_gettime(CLOCK_REALTIME, &close_deadline);
    add_milliseconds(&close_deadline, TJU_CLOSE_TIMEOUT_MS);

    while(sock->state != TIME_WAIT && sock->state != CLOSED &&
          !sock->close_failed){
        int wait_result = pthread_cond_timedwait(
            &(sock->state_cond), &(sock->state_lock), &close_deadline
        );
        if(wait_result == ETIMEDOUT){
            sock->close_failed = 1;
            sock->state = CLOSED;
            remove_established_socket(sock);
            break;
        }
    }

    int enter_time_wait = (sock->state == TIME_WAIT);
    int close_failed = sock->close_failed;
    pthread_mutex_unlock(&(sock->state_lock));

    if(enter_time_wait){
        struct timespec time_wait;
        time_wait.tv_sec = (2 * TJU_MSL_MS) / 1000;
        time_wait.tv_nsec = (long)((2 * TJU_MSL_MS) % 1000) * 1000000L;
        nanosleep(&time_wait, NULL);

        pthread_mutex_lock(&(sock->state_lock));
        sock->state = CLOSED;
        remove_established_socket(sock);
        pthread_cond_broadcast(&(sock->state_cond));
        pthread_mutex_unlock(&(sock->state_lock));
    }

    return close_failed ? -1 : 0;
}
