#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <pthread.h>

#define CERT_PATH "server/cert.pem"
#define PKEY_PATH "server/pkey.pem"

// Verify certificate callback
int ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
}

// Generate cookie callback
int app_gen_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    return 1;
}

// Verify cookie callback
int app_verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return 1;
}

void *handle_connection(void *arg)
{
    SSL *ssl;

    int cnt = 0;

    char buf[BUFSIZ];

    while (1)
    {
        int len = SSL_read(ssl, buf, BUFSIZ);
        switch (SSL_get_error(ssl, len))
        {
        case SSL_ERROR_NONE:
        {
            ++cnt;
            printf("Received %d datagrams\n", cnt);
            break;
        }
        default:
        {
            ERR_print_errors_fp(stderr);
        }
        }

        // len = SSL_write(ssl, buf, strlen(buf) + 1);
        // switch (SSL_get_error(ssl, len))
        // {
        // case SSL_ERROR_NONE:
        // {
        //     reading = 0;
        //     break;
        // }
        // default:
        // {
        //     ERR_print_errors_fp(stderr);
        // }
        // }
    }
}

int start_server(int port)
{
    // New SSL context
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_use_certificate_chain_file(ctx, CERT_PATH);
    SSL_CTX_use_PrivateKey_file(ctx, PKEY_PATH, SSL_FILETYPE_PEM);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_verify_cb);
    SSL_CTX_set_cookie_generate_cb(ctx, app_gen_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(ctx, app_verify_cookie_cb);

    // Create UDP socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        return -1;
    }

    // Configure server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Give the socket server address
    if (bind(fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1)
    {
        return -1;
    }

    while (1)
    {
        BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        // Set socket receive timeout
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        SSL *ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);

        // Enable cookie exchange
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        struct sockaddr_in *client_addr = malloc(sizeof(struct sockaddr_in));
        memset(client_addr, 0, sizeof(struct sockaddr_in));
        // Wait for incoming connections
        while (!DTLSv1_listen(ssl, (BIO_ADDR *)client_addr))
            ;

        int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (client_fd == -1)
        {
            return -1;
        }

        if (bind(client_fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1)
        {
            return -1;
        }

        if (connect(client_fd, (const struct sockaddr *)client_addr, sizeof(struct sockaddr_in)) == -1)
        {
            return -1;
        }

        BIO *cbio = SSL_get_rbio(ssl);
        BIO_set_fd(cbio, client_fd, BIO_NOCLOSE);
        BIO_ctrl_set_connected(bio, client_addr);

        SSL_accept(ssl);
        ERR_print_errors_fp(stderr);

        pthread_t connection_handling_thread;
        pthread_create(&connection_handling_thread, NULL, handle_connection, (void *)ssl);
    }

    return 0;
}

int main(int argc, char const *argv[])
{
    OPENSSL_init_ssl(0, NULL);

    int port = atoi(argv[1]);

    return start_server(port);
}
