#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>

#define CERT_PATH "client/cert.pem"
#define PKEY_PATH "client/pkey.pem"

int ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
}

int app_gen_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    return 1;
}

int app_verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return 1;
}

void *send_dgram(void *arg)
{
    SSL *ssl = (SSL *)arg;
    int cnt = 0;

    char buf[BUFSIZ];
    strcpy(buf, "abc");

    while (1)
    {
        int len = SSL_write(ssl, buf, strlen(buf) + 1);
        switch (SSL_get_error(ssl, len))
        {
            case SSL_ERROR_NONE:
            {
                ++cnt;
                printf("Sent %d datagrams\n", cnt);
                break;
            }
            default:
            {
                ERR_print_errors_fp(stderr);
            }
        }
    }
}

int start_client(char *ip, int port)
{
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_use_certificate_chain_file(ctx, CERT_PATH);
    SSL_CTX_use_PrivateKey_file(ctx, PKEY_PATH, SSL_FILETYPE_PEM);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_verify_cb);
    SSL_CTX_set_cookie_generate_cb(ctx, app_gen_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(ctx, app_verify_cookie_cb);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    if (inet_pton(AF_INET, (const char *)ip, &server_addr.sin_addr.s_addr) == -1)
    {
        return -1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (connect(fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        return -1;
    }

    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    SSL_connect(ssl);
    ERR_print_errors_fp(stderr);

    pthread_t sending_thread;
    pthread_create(&sending_thread, NULL, send_dgram, (void *)ssl);

    pthread_join(sending_thread, NULL);

    // pthread_t receiving_thread;
    // pthread_create(&receiving_thread, NULL, receive_dgram, (void *)ssl);

    return 0;
}

int main(int argc, char const *argv[])
{
    OPENSSL_init_ssl(0, NULL);

    int port = atoi(argv[2]);

    return start_client((char *)argv[1], port);
}
