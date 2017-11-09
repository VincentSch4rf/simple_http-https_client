//TODO: Test Windows
#ifdef __linux__
#define OS_Linux
#elif defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
#define OS_Windows
#endif

/* Generic */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Network */
#ifdef OS_Linux

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>

#define error(x) error(x) //error printout
#elif defined(OS_Windows)
#include <winsock2.h>
#include <stdint.h>
#pragma comment(lib,"ws2_32.lib")
//Macros
#define close(x) closesocket(x) //close socket
#define error(x) printf("%s Error: %d", x, WSAGetLastError())   //error printout
#endif

#define BUF_SIZE 100

char req[1000] = {0};

// Get host information (used to establishConnection)
struct addrinfo *getHostInfo(char *host, char *port) {
    int r;
    struct addrinfo hints, *getaddrinfo_res;
    // Setup hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if ((r = getaddrinfo(host, port, &hints, &getaddrinfo_res))) {
        char err[1024];
        sprintf(err, "[getHostInfo:getaddrinfo] %s\n", gai_strerror(r));
        error(err);
        return NULL;
    }

    return getaddrinfo_res;
}

// Establish connection with host
int establishConnection(struct addrinfo *info) {
    if (info == NULL) return -1;
#ifdef OS_Windows
    //initializations for winsock
    WSADATA wsa;
    SOCKET clientfd;
    printf("Initializing WINSock...");
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        error("wsainit");
        exit(EXIT_FAILURE);
    }
    printf("Initialized!\n");
#elif defined(OS_Linux)
    //initialisations for unix
    int clientfd;
#endif
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
    return -1;
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
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else
        printf("Info: No client certificates configured.\n");
}

void read_ssl_response(SSL *ssl, char *buf) {
    while (1) {
        int bytes = SSL_read(ssl, buf, BUF_SIZE);
        if (bytes < 0) {
            error("SSL_read");
        } else if (bytes == 0) {
            break;
        }
        fputs(buf, stdout);
        memset(buf, 0, BUF_SIZE);
    }
}

void read_response(int clientfd, char *buf) {
    while (1) {
        int bytes = read(clientfd, buf, BUF_SIZE);
        if (bytes < 0) {
            error("read");
        } else if (bytes == 0) {
            break;
        }
        fputs(buf, stdout);
        memset(buf, 0, BUF_SIZE);
    }
}


// Send GET request
char *GET(int clientfd, char *path) {
    memset(req, 0, sizeof(req));
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n", path);
    write(clientfd, req, strlen(req));
    return req;
}

// Send POST request
char *POST(int clientfd, char *path, char *argument) {
    memset(req, 0, sizeof(req));
    sprintf(req, "POST %s HTTP/1.0\r\n\r\n%s", path, argument);
    write(clientfd, req, strlen(req));
    return req;
}


// Send PUSH request
char *PUT(int clientfd, char *path, char *content) {
    memset(req, 0, sizeof(req));
    sprintf(req, "PUT %s HTTP/1.0\r\n\r\n %s", path, content);
    write(clientfd, req, strlen(req));
    return req;
}

// Send GET request over TSL
char *SSL_GET(SSL *ssl, char *path) {
    memset(req, 0, sizeof(req));
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n", path);
    if (SSL_write(ssl, req, strlen(req)) < 0) {
        fprintf(stderr, "SSL_ERROR: SSL_write");
    }
    return req;
}

// Send POST request over TSL
char *SSL_POST(SSL *ssl, char *path, char *argument) {
    memset(req, 0, sizeof(req));
    sprintf(req, "POST %s HTTP/1.0\r\n\r\n%s", path, argument);
    if (SSL_write(ssl, req, strlen(req)) < 0) {
        fprintf(stderr, "SSL_ERROR: SSL_write");
    }
    return req;
}

// Send PUT request over TSL
char *SSL_PUT(SSL *ssl, char *path, char *content) {
    memset(req, 0, sizeof(req));
    sprintf(req, "PUT %s HTTP/1.0\r\n\r\n %s", path, content);
    if (SSL_write(ssl, req, strlen(req)) < 0) {
        fprintf(stderr, "SSL_ERROR: SSL_write");
    }
    return req;
}

int main(int argc, char **argv) {
    int https = 0;
    int clientfd;
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
                argv[1], argv[2], argv[4]);
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
            char *request = SSL_GET(ssl, argv[4]);
            printf("Send request: %s to server. Waiting for reply...\n", request);
            printf("Server reply:\n");
            read_ssl_response(ssl, buf);
        } else if (strcmp(argv[3], "POST") == 0) {
            // Send SSL_POST request > stdout
            char *request = SSL_POST(ssl, argv[4], argv[5]);
            printf("Send request: %s to server. Waiting for reply...\n", request);
            printf("Server reply:\n");
            read_ssl_response(ssl, buf);
        } else if (strcmp(argv[3], "PUT") == 0) {
            // Send SSL_PUT request > stdout
            char *request = SSL_PUT(ssl, argv[4], argv[5]);
            printf("Send request: %s to server. Waiting for reply...\n", request);
            printf("Server reply:\n");
            read_ssl_response(ssl, buf);
        }
        SSL_free(ssl);
    } else {
        if (strcmp(argv[3], "GET") == 0) {
            // Send GET request > stdout
            char *request = GET(clientfd, argv[4]);
            printf("Send request: %s to server. Waiting for reply...\n", request);
            printf("Server reply:\n");
            read_response(clientfd, buf);
        } else if (strcmp(argv[3], "POST") == 0) {
            // Send POST request > stdout
            char *request = POST(clientfd, argv[4], argv[5]);
            printf("Send request: %s to server. Waiting for reply...\n", request);
            printf("Server reply:\n");
            read_response(clientfd, buf);
        } else if (strcmp(argv[3], "PUT") == 0) {
            // Send PUT request > stdout
            char *request = PUT(clientfd, argv[4], argv[5]);
            printf("Send request: %s to server. Waiting for reply...\n", request);
            printf("Server reply:\n");
            read_response(clientfd, buf);
        }
    }
    close(clientfd);
#ifdef OS_Windows
    WSACleanup();
#endif
    return 0;
}