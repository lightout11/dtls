#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#define CERT_PATH "server/cert.pem"
#define PKEY_PATH "server/pkey.pem"

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

int start_server(int port)
{
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
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
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;

    if (bind(fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1)
    {
        return -1;
    }

    while (1)
    {
        BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);

        SSL *ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        struct sockaddr_in *client_addr = malloc(sizeof(struct sockaddr_in));
        while (!DTLSv1_listen(ssl, (BIO_ADDR *)client_addr));

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
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, client_addr);

        SSL_accept(ssl);
    }
}

int main(int argc, char const *argv[])
{
    OPENSSL_init_ssl(0, NULL);
    return 0;
}
