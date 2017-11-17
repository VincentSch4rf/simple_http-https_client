//TODO: Test Windows
#ifdef __linux__
#define OS_Linux
#elif defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
#define OS_Windows
#endif

#ifdef OS_Windows
#define _WIN32_WINNT 0x0501
#endif
/* Generic */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

/* Network */
#ifdef OS_Linux
#include <netdb.h>
#include <sys/socket.h>
//Macros
#define SOCKET int
#define SOCK_ERROR '-1'
#define error(x) error(x) //error printout
#elif defined(OS_Windows)
#include <winsock2.h>
#include <ws2tcpip.h>
//Macros
#define close(x) closesocket(x) //close socket
#define error(x) printf("%s Error: %d", x, WSAGetLastError())   //error printout
#define SOCK_ERROR NULL
#endif

#define BUF_SIZE 100

char req[1000] = {0};

// Get host information (used to establishConnection)
struct addrinfo *getHostInfo(char *host, char *port) {
    //Initialize WSA for Windows
#ifdef OS_Windows
    WSADATA wsa;
    printf("Initializing WINSock...");
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        error("wsainit");
        exit(EXIT_FAILURE);
    }
#endif
    int r;
    struct addrinfo hints, *getaddrinfo_res;
    // Setup hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ((r = getaddrinfo(host, port, &hints, &getaddrinfo_res)) != 0) {
        char err[1024];
        sprintf(err, "[getHostInfo:getaddrinfo] %s\n", gai_strerror(r));
        error(err);
        return NULL;
    }

    return getaddrinfo_res;
}

// Establish connection with host
SOCKET establishConnection(struct addrinfo *info) {
    if (info == NULL) return SOCK_ERROR;
    SOCKET clientfd;
    printf("Initialized!\n");
    for (; info != NULL; info = info->ai_next) {
        if ((clientfd = socket(info->ai_family,
                               info->ai_socktype,
                               info->ai_protocol)) < 0) {
            error("[establishConnection:socket]");
            continue;
        }

        if (connect(clientfd, info->ai_addr, info->ai_addrlen) < 0) {
            close(clientfd);
            error("[establishConnection:connect]");
            continue;
        }

        freeaddrinfo(info);
        return clientfd;
    }

    freeaddrinfo(info);
    return SOCK_ERROR;
}

//Show certificate
void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
#ifdef OS_Linux
        free(line);       /* free the malloc'ed string */
#endif
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
#ifdef OS_Linux
        free(line);       /* free the malloc'ed string */
#endif
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else
        printf("Info: No client certificates configured.\n");
}

int read_ssl_response(SSL *ssl, char *buf) {
    int bytes_read = 0;
    while (1) {
        int bytes = SSL_read(ssl, buf, BUF_SIZE);
        if (bytes < 0) {
            error("SSL_read");
        } else if (bytes == 0) {
            break;
        }
        bytes_read += bytes;
        fputs(buf, stdout);
        memset(buf, 0, BUF_SIZE);
    }
    return bytes_read;
}

int read_response(int clientfd, char *buf) {
    int bytes_read = 0;
    while (1) {
        int bytes = read(clientfd, buf, BUF_SIZE);
        if (bytes < 0) {
            error("read");
        } else if (bytes == 0) {
            break;
        }
        bytes_read += bytes;
        fputs(buf, stdout);
        memset(buf, 0, BUF_SIZE);
    }
}


// Send GET request
char *GET(int clientfd, char *path, char *host) {
    memset(req, 0, sizeof(req));
    sprintf(req, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host);
    write(clientfd, req, strlen(req));
    return req;
}

// Send POST request
char *POST(int clientfd, char *path, char *host, char *argument) {
    memset(req, 0, sizeof(req));
    sprintf(req, "POST %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", path, host, argument);
    write(clientfd, req, strlen(req));
    return req;
}


// Send PUSH request
char *PUT(int clientfd, char *path, char *host, char *content) {
    memset(req, 0, sizeof(req));
    sprintf(req, "PUT %s HTTP/1.1\r\nHost: %s\r\n\r\n %s", path, host, content);
    write(clientfd, req, strlen(req));
    return req;
}

// Send GET request over TLS
char *SSL_GET(SSL *ssl, char *path, char *host) {
    memset(req, 0, sizeof(req));
    sprintf(req, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host);
    if (SSL_write(ssl, req, strlen(req)) < 0) {
        fprintf(stderr, "SSL_ERROR: SSL_write");
    }
    return req;
}

// Send POST request over TLS
char *SSL_POST(SSL *ssl, char *path, char *host, char *argument) {
    memset(req, 0, sizeof(req));
    sprintf(req, "POST %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", path, host, argument);
    if (SSL_write(ssl, req, strlen(req)) < 0) {
        fprintf(stderr, "SSL_ERROR: SSL_write");
    }
    return req;
}

// Send PUT request over TLS
char *SSL_PUT(SSL *ssl, char *path, char *host, char *content) {
    memset(req, 0, sizeof(req));
    sprintf(req, "PUT %s HTTP/1.1\r\nHost: %s\r\n\r\n %s", path, host, content);
    if (SSL_write(ssl, req, strlen(req)) < 0) {
        fprintf(stderr, "SSL_ERROR: SSL_write");
    }
    return req;
}

int main(int argc, char **argv) {
    int https = 0;
    SOCKET clientfd;
    char buf[BUF_SIZE];
    SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL *ssl = SSL_new(ctx);

    if (argc < 5) {
        fprintf(stderr, "USAGE: ./httpclient <hostname> <port> <request type> <request path> <message body>\n");
        return 1;
    }

    // Check if we are speaking to an SSL enabled socket
    if(strcmp(argv[2],"443") == 0) {
        https = 1;
    }

    // Establish connection with <hostname>:<port>
    clientfd = establishConnection(getHostInfo(argv[1], argv[2]));
    if (clientfd == -1) {
        fprintf(stderr,
                "Failed to connect to: %s:%s%s \n",
                argv[1], argv[2], argv[3]);
        return 3;
    }

    /* If the socket we are connected to is SSL enabled, speak HTTPS
     * Else speak plain HTTP */
    if(https == 1)
    {
        SSL_set_fd(ssl, clientfd);
        SSL_connect(ssl);
        ShowCerts(ssl);
        printf("Connected with cipher: %s!\n", SSL_get_cipher(ssl));
        if (strcmp(argv[3], "GET") == 0) {
            // Send SSL_GET request > stdout
            char *request = SSL_GET(ssl, argv[4], argv[1]);
            printf("Send request: %sto server. Waiting for reply...\n\n", request);
            printf("Server reply:\n");
            int bytes = read_ssl_response(ssl, buf);
            printf("Bytes read: %d", bytes);
        } else if (strcmp(argv[3], "POST") == 0) {
            // Send SSL_POST request > stdout
            char *request = SSL_POST(ssl, argv[4], argv[1], argv[5]);
            printf("Send request: %sto server. Waiting for reply...\n\n", request);
            printf("Server reply:\n");
            int bytes = read_ssl_response(ssl, buf);
            printf("Bytes read: %d", bytes);
        } else if (strcmp(argv[3], "PUT") == 0) {
            // Send SSL_PUT request > stdout
            char *request = SSL_PUT(ssl, argv[4], argv[1], argv[5]);
            printf("Send request: %sto server. Waiting for reply...\n\n", request);
            printf("Server reply:\n");
            int bytes = read_ssl_response(ssl, buf);
            printf("Bytes read: %d", bytes);
        }
        // Close SSL connection
        SSL_free(ssl);
    } else {
        if (strcmp(argv[3], "GET") == 0) {
            // Send GET request > stdout
            char *request = GET(clientfd, argv[4], argv[1]);
            printf("Send request: %s to server. Waiting for reply...\n\n", request);
            printf("Server reply:\n");
            int bytes = read_response(clientfd, buf);
            printf("Bytes read: %d", bytes);
        } else if (strcmp(argv[3], "POST") == 0) {
            // Send POST request > stdout
            char *request = POST(clientfd, argv[4], argv[1], argv[5]);
            printf("Send request: %s to server. Waiting for reply...\n\n", request);
            printf("Server reply:\n");
            int bytes = read_response(clientfd, buf);
            printf("Bytes read: %d", bytes);
        } else if (strcmp(argv[3], "PUT") == 0) {
            // Send PUT request > stdout
            char *request = PUT(clientfd, argv[4], argv[1], argv[5]);
            printf("Send request: %s to server. Waiting for reply...\n\n", request);
            printf("Server reply:\n");
            int bytes = read_response(clientfd, buf);
            printf("Bytes read: %d", bytes);
        }
    }
    // Close socket
    close(clientfd);
#ifdef OS_Windows
    WSACleanup();
#endif
    return 0;
}