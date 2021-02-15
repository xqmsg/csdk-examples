//
//  proxy.h
//  xq-examples
//
//

#ifndef __PIDEMO_H__
#define __PIDEMO_H__

#define BACKLOG 32
#define MAX_BUFFER 64000
#define QUANTUM_LENGTH 256
#define HEX_LENGTH ( QUANTUM_LENGTH >> 2 )
#define EXPANDED_HEX_LENGTH 256
#define TOKEN_SIZE 43
#define MAX_RECIPIENTS 100


struct route_config {
    struct sockaddr_in address;
    int socket_fd;
};

struct server_config {
    struct xq_config* config;
    struct xq_quantum_pool pool;
    const char* host_adress;
    const char* user;
    const char* recipients;
    int recipient_len; // The number of recipients specified.
    char active_read_token[TOKEN_SIZE + 1 ];
    char active_write_token[TOKEN_SIZE + 1 ];
    char active_write_key[EXPANDED_HEX_LENGTH + 1];
    char active_read_key[EXPANDED_HEX_LENGTH + 1];
    int max_key_usage;  //Number of times key can be used before rotation.
    int key_usage;
    _Bool key_ready;
    struct route_config enc_route;
    struct route_config dec_route;
    struct route_config outgoing_enc;
    struct route_config outgoing_dec;
    _Bool failed_token;
    int passthrough;
    int algorithm; // 1 = OTP, 2 = AES
    
    struct route_config dump_route;
    pthread_attr_t pthread_attr;
};

typedef struct xq_net_packet (*data_handler)(struct xq_net_packet);

typedef struct pthread_arg_t {
    int new_socket_fd;
    struct sockaddr_in client_address;
    struct server_config* svr;
    size_t bytes_read;
    uint8_t buffer[MAX_BUFFER];
} pthread_arg_t;


/* Thread routines to serve connection to client. */
void *encrypt_data_handler(void *arg);
void *decrypt_data_handler(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler(int signal_number);

#endif



