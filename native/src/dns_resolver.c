#ifdef _WIN32
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dns_brute.h"

#ifdef _WIN32
static int winsock_initialized = 0;

static void init_winsock(void) {
    if (!winsock_initialized) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        winsock_initialized = 1;
    }
}
#endif

int dns_resolve(const char *hostname, char *ip_out, size_t ip_len) {
#ifdef _WIN32
    init_winsock();
#endif
    
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0) {
        return -1;
    }
    
    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_out, ip_len);
            freeaddrinfo(res);
            return 0;
        }
    }
    
    freeaddrinfo(res);
    return -1;
}

bool detect_wildcard(const char *domain, char *wildcard_ip) {
    char random_sub[MAX_DOMAIN_LEN];
    char ip1[MAX_IP_LEN], ip2[MAX_IP_LEN], ip3[MAX_IP_LEN];
    
    snprintf(random_sub, sizeof(random_sub), "xq7z9k2m1p.%s", domain);
    if (dns_resolve(random_sub, ip1, sizeof(ip1)) != 0) {
        return false;
    }
    
    snprintf(random_sub, sizeof(random_sub), "j8h3n5w0v6.%s", domain);
    if (dns_resolve(random_sub, ip2, sizeof(ip2)) != 0) {
        return false;
    }
    
    snprintf(random_sub, sizeof(random_sub), "b4y1c9f2l7.%s", domain);
    if (dns_resolve(random_sub, ip3, sizeof(ip3)) != 0) {
        return false;
    }
    
    if (strcmp(ip1, ip2) == 0 && strcmp(ip2, ip3) == 0) {
        strncpy(wildcard_ip, ip1, MAX_IP_LEN - 1);
        wildcard_ip[MAX_IP_LEN - 1] = '\0';
        return true;
    }
    
    return false;
}
