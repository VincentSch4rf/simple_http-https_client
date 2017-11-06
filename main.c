/* Generic */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Network */
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>

#define BUF_SIZE 100

// Get host information (used to establishConnection)
struct addrinfo *getHostInfo(char* host, char* port) {
    int r;
    struct addrinfo hints, *getaddrinfo_res;
    // Setup hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if ((r = getaddrinfo(host, port, &hints, &getaddrinfo_res))) {
        fprintf(stderr, "[getHostInfo:21:getaddrinfo] %s\n", gai_strerror(r));
        return NULL;
    }

    return getaddrinfo_res;
}

// Establish connection with host
int establishConnection(struct addrinfo *info) {
    if (info == NULL) return -1;

    int clientfd;
    for (;info != NULL; info = info->ai_next) {
        if ((clientfd = socket(info->ai_family,
                               info->ai_socktype,
                               info->ai_protocol)) < 0) {
            perror("[establishConnection:35:socket]");
            continue;
        }

        if (connect(clientfd, info->ai_addr, info->ai_addrlen) < 0) {
            close(clientfd);
            perror("[establishConnection:42:connect]");
            continue;
        }

        freeaddrinfo(info);
        return clientfd;
    }

    freeaddrinfo(info);
    return -1;
}

//Show certificate
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

// Send GET request
void GET(int clientfd, char *path) {
    char req[1000] = {0};
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n", path);
    write(clientfd, req, strlen(req));
}

void SSL_GET(SSL *ssl, char *path) {
    char req[1000] = {0};
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n", path);
    SSL_write(ssl, req, strlen(req));
}

int main(int argc, char **argv) {
    SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL *ssl = SSL_new(ctx);

    int clientfd;
    char buf[BUF_SIZE];

    if (argc != 4) {
        fprintf(stderr, "USAGE: ./httpclient <hostname> <port> <request path>\n");
        return 1;
    }

    // Establish connection with <hostname>:<port>
    clientfd = establishConnection(getHostInfo(argv[1], argv[2]));

    SSL_set_fd(ssl, clientfd);
    SSL_connect(ssl);

    if (clientfd == -1) {
        fprintf(stderr,
                "[main:73] Failed to connect to: %s:%s%s \n",
                argv[1], argv[2], argv[3]);
        return 3;
    }

    ShowCerts(ssl);
    printf("Connected with cipher: %s!\n",SSL_get_cipher(ssl));
    printf("\n\nServer reply:\n");
    // Send SSL_GET request > stdout
    SSL_GET(ssl, argv[3]);
    while (SSL_read(ssl, buf, BUF_SIZE) > 0) {
        fputs(buf, stdout);
        memset(buf, 0, BUF_SIZE);
    }

    close(clientfd);
    return 0;
}