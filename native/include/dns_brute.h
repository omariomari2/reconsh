#ifndef DNS_BRUTE_H
#define DNS_BRUTE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define MAX_DOMAIN_LEN 256
#define MAX_IP_LEN 64
#define MAX_WORKERS 256
#define DEFAULT_WORKERS 50

typedef struct {
    char subdomain[MAX_DOMAIN_LEN];
    char ip[MAX_IP_LEN];
    bool resolved;
} dns_result_t;

typedef struct {
    char *domain;
    char *wordlist_path;
    char *output_path;
    int workers;
    bool json_output;
    bool verbose;
    bool detect_wildcard;
} dns_config_t;

typedef struct {
    char **words;
    size_t count;
    size_t capacity;
} wordlist_t;

typedef struct {
    dns_config_t *config;
    wordlist_t *wordlist;
    dns_result_t *results;
    size_t results_count;
    size_t results_capacity;
    size_t current_index;
    size_t completed;
    bool wildcard_detected;
    char wildcard_ip[MAX_IP_LEN];
    pthread_mutex_t index_lock;
    pthread_mutex_t results_lock;
} brute_context_t;

int dns_resolve(const char *hostname, char *ip_out, size_t ip_len);
bool detect_wildcard(const char *domain, char *wildcard_ip);
wordlist_t *load_wordlist(const char *path);
void free_wordlist(wordlist_t *wl);
int run_bruteforce(dns_config_t *config);
void output_results_json(brute_context_t *ctx, FILE *out);
void output_results_text(brute_context_t *ctx, FILE *out);

#endif
