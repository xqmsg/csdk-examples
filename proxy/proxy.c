//
//  proxy.c
//  xq-examples
//
// Note: this example demonstrates how to create a data encryption proxy server using XQ, and is not suitable for
// production.

#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <xq/xq.h>
#include "proxy.h"


void *encrypt_data_handler( void* args ){
    
    struct pthread_arg_t *pthread_args = (struct pthread_arg_t *)args;
    struct server_config *svr =  pthread_args->svr;
    
    if (svr->dump_route.address.sin_port > 0) {
        sendto(svr->dump_route.socket_fd, pthread_args->buffer,  pthread_args->bytes_read,
               MSG_DONTWAIT, (const struct sockaddr *) &svr->dump_route.address,
               sizeof (struct sockaddr_in) );
    }
    
    
    // If the passthrough flag is set, the data is retransmitted untouched.
    if (svr->passthrough == 1) {
        sendto(svr->outgoing_enc.socket_fd, pthread_args->buffer,  pthread_args->bytes_read,
               MSG_DONTWAIT, (const struct sockaddr *) &svr->outgoing_enc.address,
               sizeof (struct sockaddr_in) );
        return 0;
    }
    
    struct xq_error_info err;
    
    // Check whether it is time to fetch new quantum entropy. Due to the sheer volume of data
    // that may be streamed, we want to have our quantum entropy cached and reused for a user-determined number
    // of times before being updated.
    if ( !svr->key_ready ||  svr->key_usage >= svr->max_key_usage) {
        
        // Use a preallocated buffer. Alternatively, we could dynamically allocate an array, as long as it is
        // cleaned up properly after use.
        char raw_entropy[ QUANTUM_LENGTH + 1 ] = {0};
        struct xq_quantum_key quantum = { raw_entropy, QUANTUM_LENGTH };
        
        // Fetch the entropy bytes from the server.
        if ( !xq_svc_quantum( svr->config, &quantum, &svr->pool , &err ) ) {
            fprintf(stderr, "Failed to get entropy: %s", err.content );
            return 0;
        }
        
        // Create a buffer to hold our hex bytes.
        char key_content[ HEX_LENGTH + 1 ] = {0};
        struct xq_hex_quantum_key hex_key = { key_content, HEX_LENGTH  };
        
        // Convert our entropy bytes to hex.
        xq_key_to_hex(&quantum, &hex_key, 0);
        
        // Programmatically expand our hex key as required.
        xq_expand_key(key_content, svr->active_write_key, EXPANDED_HEX_LENGTH );
        
        memset(svr->active_write_token, 0, sizeof(svr->active_write_token));
        
        struct xq_message_token result = { svr->active_write_token, TOKEN_SIZE };
        
        struct xq_message_token_request request = {
            svr->active_write_key, // The key to store
            EXPANDED_HEX_LENGTH, // The length of the key
            svr->recipients, // The recipients who have access to the key.
            24, // expire tokens in 24 hours
            0, // delete on read
            "data"
        };
        
        if (!xq_svc_store_key(svr->config, &request, &result, &err) ) {
            fprintf(stderr, "Failed to store key: %s\n", err.content );
            return 0;
        }
        
        // Reset our usage and ready flags.
        svr->key_usage = 0;
        svr->key_ready = 1;
        
        printf("Current Token: %s\n", svr->active_write_token);
        
    }
    
    uint8_t out[MAX_BUFFER] = {0};
    
    struct xq_message_payload payload = {  out + TOKEN_SIZE , MAX_BUFFER - TOKEN_SIZE };
    
    // Copy the token to the output buffer.
    memccpy(out, svr->active_write_token, '\0', TOKEN_SIZE );
    
    // OTP
    _Bool success = (svr->algorithm == 2) ? \
    xq_aes_encrypt(pthread_args->buffer, pthread_args->bytes_read, svr->active_write_key, &payload, &err ) : \
    xq_otp_encrypt(pthread_args->buffer, pthread_args->bytes_read, svr->active_write_key, &payload, &err );
    
    // Encrypt the content
    if (!success) {
        printf("Failed to encrypt payload:%s \n", err.content );
    }
    
    
    else {
        
        ++svr->key_usage;
        ssize_t bytes_sent = sendto(svr->outgoing_enc.socket_fd, out, payload.length + TOKEN_SIZE ,
                                    MSG_DONTWAIT, (const struct sockaddr *) &svr->outgoing_enc.address,
                                    sizeof (struct sockaddr_in) );
        
    }
    return 0;
}

void *start_encryption_listener(void *args ) {
    
    struct server_config *svr = (struct server_config *)args;
    
    /* Create TCP socket for incoming data. */
    if ((svr->enc_route.socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    /* Bind incoming address to socket. */
    if (bind(svr->enc_route.socket_fd, (struct sockaddr *)&svr->enc_route.address, sizeof (struct sockaddr_in) ) == -1) {
        fprintf( stderr, "Error on binding encryption route address.\n");
        perror("bind");
        exit(EXIT_FAILURE);
    }
    
    /* Create socket for outgoing data. */
    if ((svr->outgoing_enc.socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    /* Create socket for data dump. */
    if (svr->dump_route.address.sin_port > 0) {
        if ((svr->dump_route.socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
    }
    
    int new_socket_fd;
    pthread_t pthread;
    socklen_t client_address_len;
    
    while (1) {
        
        struct pthread_arg_t pthread_arg = {0};
        
        /* Accept connection to client. */
        client_address_len = sizeof pthread_arg.client_address;
        
        pthread_arg.bytes_read = recvfrom(svr->enc_route.socket_fd, (char *)pthread_arg.buffer, MAX_BUFFER,
                                          MSG_WAITALL, ( struct sockaddr *) &pthread_arg.client_address,
                                          &client_address_len);
        
        if (pthread_arg.bytes_read == -1) {
            perror("recfrom");
            exit(EXIT_FAILURE);
        }
        
        
        if (pthread_arg.bytes_read > 0) {
            pthread_arg.svr = svr;
            encrypt_data_handler( &pthread_arg );
        }
    }
}


void *decrypt_data_handler( void* args ){
    
    struct pthread_arg_t *pthread_args = (struct pthread_arg_t *)args;
    
    // Write out received buffer to target.
    struct server_config *svr =  pthread_args->svr;
    
    if (svr->passthrough == 1) {
        ssize_t bytes_sent = sendto(svr->outgoing_dec.socket_fd, pthread_args->buffer,  pthread_args->bytes_read,
                                    MSG_DONTWAIT, (const struct sockaddr *) &svr->outgoing_dec.address,
                                    sizeof (struct sockaddr_in) );
        return 0;
    }
    
    struct xq_error_info err = {0};
    
    if (pthread_args->bytes_read < TOKEN_SIZE ) {
        fprintf(stderr, "Not enough bytes read.\n");
        return 0;
    }
    
    struct xq_key k = { svr->active_read_key, EXPANDED_HEX_LENGTH };
    
    // If the token is different, attempt to pull the key from the server.
    if ( 0 != strncmp((const char*) pthread_args->buffer, svr->active_read_token, TOKEN_SIZE ) ) {
        
        memccpy(svr->active_read_token, pthread_args->buffer, '\0', TOKEN_SIZE);
        
        if (!xq_svc_get_key(svr->config, svr->active_read_token, &k, &err)) {
            svr->failed_token = 0;
            fprintf(stderr, "Failed to get key with token %s.\n(Error: %s)\n", svr->active_read_token,  err.content );
            memset(svr->active_read_key, 0, sizeof (svr->active_read_key) );
            return 0;
        }
        else  {
            printf("Got Token %s\n" , svr->active_read_token );
            
        }
    }
    
    // Decrypt the message.
    uint8_t out[MAX_BUFFER] = {0};
    struct xq_message_payload payload = {  out  , MAX_BUFFER };
    
    _Bool success = (svr->algorithm == 2) ? \
    xq_aes_decrypt(pthread_args->buffer + TOKEN_SIZE , pthread_args->bytes_read - TOKEN_SIZE, svr->active_read_key, &payload, &err ) :\
    xq_otp_decrypt(pthread_args->buffer + TOKEN_SIZE , pthread_args->bytes_read - TOKEN_SIZE, svr->active_read_key, &payload, &err );
    
    if (success) {
        sendto(svr->outgoing_dec.socket_fd, out, pthread_args->bytes_read - TOKEN_SIZE,
               MSG_DONTWAIT, (const struct sockaddr *) &svr->outgoing_dec.address,
               sizeof (struct sockaddr_in) );
    }
    
    return 0;
    
}


void *start_decryption_listener(void *args ) {
    
    struct server_config *svr = (struct server_config *)args;
    
    /* Create TCP socket. */
    if ((svr->dec_route.socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("start_decryption_listener - socket");
        exit(1);
    }
    
    /* Bind address to socket. */
    if (bind(svr->dec_route.socket_fd, (struct sockaddr *)&svr->dec_route.address, sizeof (struct sockaddr_in) ) == -1) {
        perror("start_decryption_listener - bind");
        exit(1);
    }
    
    /* Create socket for outgoing data. */
    if ((svr->outgoing_dec.socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    
    
    int new_socket_fd;
    pthread_t pthread;
    socklen_t client_address_len;
    
    while (1) {
        
        struct pthread_arg_t pthread_arg = {0};
        
        // Accept connection to client.
        client_address_len = sizeof pthread_arg.client_address;
        
        pthread_arg.bytes_read = recvfrom(svr->dec_route.socket_fd, (char *)pthread_arg.buffer, MAX_BUFFER,
                                          MSG_WAITALL, ( struct sockaddr *) &pthread_arg.client_address,
                                          &client_address_len);
        
        if (pthread_arg.bytes_read == -1) {
            perror("recfrom");
            continue;
        }
        
        if (pthread_arg.bytes_read > 0 ) {
            pthread_arg.svr = svr;
            decrypt_data_handler( &pthread_arg );
        }
        
    }
}


void signal_handler(int signal_number) {
    printf("\n** Terminating xq-proxy **\n");
    exit(0);
}


// See the README for argument descriptions.
int main(int argc, const char * argv[]) {
    
    // Seed the random number generator.
    srand((unsigned int)time(NULL));
    
    data_handler socket_callback = NULL;
    
    struct server_config svr;
    
    memset(&svr, 0, sizeof (struct server_config) );
    svr.failed_token = 0;
    svr.dump_route.address.sin_port = 0;
    svr.algorithm = 1; // Default to OTP
    const char* default_host = "0.0.0.0"; // Default server address.
    const char* default_user = "xq-proxy"; // Default XQ user if none is provided.
    int enc_port = 3081; // Standard encryption proxy port.
    int dec_port = 3082; // Standard decryption proxy port.
    int enc_out_host_index = 0; // Index of the host address, if available. Will default to default_host if not.
    int enc_out_port = 3082; // Index of the parameter containing the target endpoint. If this is not provided.
    int dec_out_host_index = 0; // Index of the host address, if available. Will default to default_host if not.
    int dec_out_port = 5000; // Index of the parameter containing the target endpoint. If this is not provided.
    int config_index = 0; // Index of the configuration file, if available. Will expand to xq.ini if not.
    int host_index = 0;
    int user_index = 0; // Index of the user to login as.
    int recipient_index = 0; // Index of recipient list. If none is provided, the signed-in user is used instead.
    int max_key_usage = 9000; // The number of time a key should be used before it is rotate.
    int dump_port = 0;// Incoming data on the encryption port will be dumped to this location. For debugging only.
    
    int value_idx = 0, i = 0;
    for (i = 1; i < argc; i+=2) {
        value_idx = i + 1;
        
        if (argc > value_idx ) {
            if (strncmp(argv[i], "-enc_in_port", 12 ) == 0) {
                enc_port = (int) strtol(argv[value_idx], NULL, 10);
            }
            else if (strncmp(argv[i], "-dec_in_port", 12 ) == 0) {
                dec_port = (int) strtol(argv[value_idx], NULL, 10);
            }
            else if (strncmp(argv[i], "-host", 5 ) == 0) {
                host_index = value_idx;
            }
            else if (strncmp(argv[i], "-enc_out_port", 13 ) == 0) {
                enc_out_port = (int) strtol(argv[value_idx], NULL, 10);
            }
            else if (strncmp(argv[i], "-enc_out_host", 13 ) == 0) {
                enc_out_host_index = value_idx;
            }
            else if (strncmp(argv[i], "-dec_out_port", 13 ) == 0) {
                dec_out_port = (int) strtol(argv[value_idx], NULL, 10);
            }
            else if (strncmp(argv[i], "-dec_out_host", 13 ) == 0) {
                dec_out_host_index = value_idx;
            }
            else if (strncmp(argv[i], "-user", 5 ) == 0) {
                user_index = value_idx;
            }
            else if (strncmp(argv[i], "-recipients", 11 ) == 0) {
                recipient_index = value_idx;
            }
            else if (strncmp(argv[i], "-rotate", 7 ) == 0) {
                max_key_usage = (int) strtol(argv[value_idx], NULL, 10);
            }
            else if (strncmp(argv[i], "-config", 7 ) == 0) {
                config_index = value_idx;
            }
            else if (strncmp(argv[i], "-passthrough", 12 ) == 0) {
                svr.passthrough = (int) strtol(argv[value_idx], NULL, 10);
            }
            else if (strncmp(argv[i], "-dump", 10 ) == 0) {
                dump_port = (int) strtol(argv[value_idx], NULL, 10);
            }
        }
    }
    
    printf("Initializing XQ Data Proxy Server...\n");
    
    const char* host = (host_index > 0 ) ? argv[host_index] : default_host;
    
    const char* dec_out_host = (dec_out_host_index > 0 ) ? argv[dec_out_host_index] : default_host;
    
    const char* enc_out_host = (enc_out_host_index > 0 ) ? argv[enc_out_host_index] : default_host;
    
    const char* config_path = (config_index > 0 ) ? argv[config_index] : "xq.ini";
    
    struct xq_config cfg = xq_init( config_path );
    
    // If no configuration was found, abort,
    if (!xq_is_valid_config(&cfg) ) {
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    svr.config = &cfg;
    svr.max_key_usage = max_key_usage;
    
    printf( svr.algorithm == 2 ? "Algorithm: AES\n" : "Algorithm: OTP\n"  );
    
    // Initialize a quantum pool.
    struct xq_error_info err;
    memset(&svr.pool, 0, sizeof(svr.pool));
    if (!xq_init_pool(&cfg, 2048, &svr.pool, &err) ) {
        printf("Failed to initialize quantum pool.\n");
        fprintf(stderr, "%s", err.content );
        xq_destroy_config(svr.config);
        exit(EXIT_FAILURE);
    }
    
    else printf("Initialized quantum pool.\n");
    
    svr.key_ready = 0;
    svr.key_usage = 0;
    svr.user = (user_index == 0) ? default_user : argv[user_index];
    
    // If an @ character is found, assume this is a real email address.
    if ( strchr(svr.user, '@') ) {
        
        if  (!xq_svc_authorize( svr.config, svr.user, &err )) {
            fprintf(stderr, "%s", err.content );
            xq_destroy_pool(&svr.pool);
            xq_destroy_config(svr.config);
            exit(EXIT_FAILURE);
        }
        
        // Wait for the user to enter a PIN.
        char pin[7] = {0};
        printf("Enter PIN: ");
        fflush(stdout);
        fgets( pin, 7, stdin );
        int read = strcspn(pin, "\n");
        if ( read > 0 ) {
            
            pin[read] = 0;
            printf("Attempting to authorize with PIN %s...\n", pin);
            if ( !xq_svc_code_validation( svr.config, pin , &err ) ) {
                fprintf(stderr, "%li, %s", err.responseCode, err.content );
                xq_destroy_pool(&svr.pool);
                xq_destroy_config(svr.config);
                exit(EXIT_FAILURE);
            }
            
        }
        else {
            printf("No PIN provided. Checking authorization state...\n");
            if  (!xq_svc_exchange( svr.config, &err )) {
                fprintf(stderr, "%li, %s", err.responseCode, err.content );
                xq_destroy_pool(&svr.pool);
                xq_destroy_config(svr.config);
                exit(EXIT_FAILURE);
            }
        }
        printf("User Authenticated.\n" );
    }
    
    // If there is no @ character, assume this is an anonymous alias
    else {
        
        if  (!xq_svc_authorize_alias( svr.config, svr.user, &err )) {
            fprintf(stderr, "%s\n", err.content );
            xq_destroy_pool(&svr.pool);
            xq_destroy_config(svr.config);
            exit(EXIT_FAILURE);
        }
    }
    
    // Retrieve the subscriber info to get the account email in use ( which
    // may not be known beforehand if an anonymous alias is used ).
    struct xq_subscriber_info info = {0};
    if (!xq_svc_get_subscriber(svr.config, &info, &err)) {
        fprintf(stderr, "%s\n", err.content );
        xq_destroy_pool(&svr.pool);
        xq_destroy_config(svr.config);
    }
    
    // Set the data recipients.
    svr.recipients =  (recipient_index == 0) ? info.mailOrPhone : argv[recipient_index] ;
    
    printf("Recipients: %s\n", svr.recipients );
    
    if (pthread_attr_init(&svr.pthread_attr) != 0) {
        perror("pthread_attr_init");
        xq_destroy_pool(&svr.pool);
        xq_destroy_config(svr.config);
        exit(EXIT_FAILURE);
    }
    
    // Prepare the encryption listener address
    {
        memset(&svr.enc_route.address, 0, sizeof svr.enc_route.address );
        inet_pton(AF_INET, host, &(svr.enc_route.address.sin_addr));
        svr.enc_route.address.sin_family = AF_INET;
        svr.enc_route.address.sin_port = htons(enc_port);
        printf(" - Incoming Encryption Endpoint =>  %s:%i \n", host, enc_port );
    }
    
    // Prepare the encryption output address
    {
        memset(&svr.outgoing_enc.address, 0, sizeof svr.outgoing_enc.address );
        inet_pton(AF_INET, enc_out_host, &(svr.outgoing_enc.address.sin_addr));
        svr.outgoing_enc.address.sin_family = AF_INET;
        svr.outgoing_enc.address.sin_port = htons(enc_out_port);
        printf(" - Outgoing Encryption Endpoint =>  %s:%i \n", enc_out_host, enc_out_port );
    }
    
    // Prepare the encryption output address
    if (dump_port > 0 ){
        
        memset(&svr.dump_route.address, 0, sizeof svr.dump_route.address );
        inet_pton(AF_INET, host, &(svr.dump_route.address.sin_addr));
        svr.dump_route.address.sin_family = AF_INET;
        svr.dump_route.address.sin_port = htons(dump_port);
        printf(" - Dump Destination Endpoint =>  %s:%i \n", host, dump_port );
    }
    
    // Prepare the decryption listener address
    {
        memset(&svr.dec_route.address, 0, sizeof svr.dec_route.address );
        inet_pton(AF_INET, host, &(svr.dec_route.address.sin_addr));
        svr.dec_route.address.sin_family = AF_INET;
        svr.dec_route.address.sin_port = htons(dec_port);
        printf(" - Incoming Decryption Endpoint =>  %s:%i \n", host, dec_port );
    }
    
    // Prepare the decryption output address
    {
        memset(&svr.outgoing_dec.address, 0, sizeof svr.outgoing_dec.address );
        inet_pton(AF_INET, dec_out_host, &(svr.outgoing_dec.address.sin_addr));
        svr.outgoing_dec.address.sin_family = AF_INET;
        svr.outgoing_dec.address.sin_port = htons(dec_out_port);
        printf(" - Outgoing Decryption Endpoint =>  %s:%i \n", dec_out_host, dec_out_port );
    }
    
    // Create thread to serve connection to client.
    pthread_t enc_listener_thread;
    if (pthread_create(&enc_listener_thread, &svr.pthread_attr, start_encryption_listener, &svr ) != 0) {
        perror("pthread_create");
        xq_destroy_pool(&svr.pool);
        xq_destroy_config(svr.config);
        exit(EXIT_FAILURE);
    }
    
    // Create thread to serve connection to client.
    pthread_t dec_listener_thread;
    if (pthread_create(&dec_listener_thread, &svr.pthread_attr, start_decryption_listener, (void *)&svr ) != 0) {
        perror("pthread_create");
        xq_destroy_pool(&svr.pool);
        xq_destroy_config(svr.config);
        exit(EXIT_FAILURE);
    }

    if (signal( SIGPIPE, SIG_IGN) == SIG_ERR ||
        signal( SIGINT, signal_handler) == SIG_ERR ||
        signal( SIGTERM, signal_handler) == SIG_ERR
        ) {
        perror("signal");
        xq_destroy_pool(&svr.pool);
        xq_destroy_config(svr.config);
        exit(EXIT_FAILURE);
    }
    
    pthread_join(enc_listener_thread, 0);
    pthread_join(dec_listener_thread, 0);
    
    return 0;
}
