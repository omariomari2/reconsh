#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include "dns_brute.h"

static const char *DEFAULT_WORDLIST[] = {
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "blog",
    "shop", "store", "app", "m", "mobile", "cdn", "static", "assets", "img",
    "images", "css", "js", "media", "vpn", "remote", "gateway", "portal",
    "secure", "login", "auth", "sso", "id", "account", "accounts", "my",
    "dashboard", "panel", "cp", "cpanel", "webmail", "email", "smtp", "pop",
    "imap", "mx", "ns", "ns1", "ns2", "dns", "dns1", "dns2", "server",
    "web", "www1", "www2", "web1", "web2", "beta", "alpha", "demo", "sandbox",
    "qa", "uat", "prod", "production", "internal", "intranet", "extranet",
    "corp", "corporate", "local", "localhost", "db", "database", "mysql",
    "postgres", "redis", "mongo", "elastic", "search", "elk", "log", "logs",
    "monitor", "monitoring", "status", "health", "metrics", "grafana",
    "prometheus", "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "jira", "confluence", "wiki", "docs", "documentation", "support", "help",
    "ticket", "tickets", "crm", "erp", "hr", "finance", "sales", "marketing",
    NULL
};

wordlist_t *load_wordlist(const char *path) {
    wordlist_t *wl = malloc(sizeof(wordlist_t));
    wl->count = 0;
    wl->capacity = 1024;
    wl->words = malloc(sizeof(char *) * wl->capacity);
    
    if (path == NULL) {
        for (int i = 0; DEFAULT_WORDLIST[i] != NULL; i++) {
            if (wl->count >= wl->capacity) {
                wl->capacity *= 2;
                wl->words = realloc(wl->words, sizeof(char *) * wl->capacity);
            }
            wl->words[wl->count++] = strdup(DEFAULT_WORDLIST[i]);
        }
        return wl;
    }
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open wordlist: %s\n", path);
        free(wl->words);
        free(wl);
        return NULL;
    }
    
    char line[MAX_DOMAIN_LEN];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;
        
        if (wl->count >= wl->capacity) {
            wl->capacity *= 2;
            wl->words = realloc(wl->words, sizeof(char *) * wl->capacity);
        }
        wl->words[wl->count++] = strdup(line);
    }
    
    fclose(fp);
    return wl;
}

void free_wordlist(wordlist_t *wl) {
    if (!wl) return;
    for (size_t i = 0; i < wl->count; i++) {
        free(wl->words[i]);
    }
    free(wl->words);
    free(wl);
}

static void add_result(brute_context_t *ctx, const char *subdomain, const char *ip) {
    pthread_mutex_lock(&ctx->results_lock);
    
    if (ctx->results_count >= ctx->results_capacity) {
        ctx->results_capacity *= 2;
        ctx->results = realloc(ctx->results, sizeof(dns_result_t) * ctx->results_capacity);
    }
    
    dns_result_t *r = &ctx->results[ctx->results_count++];
    strncpy(r->subdomain, subdomain, MAX_DOMAIN_LEN - 1);
    strncpy(r->ip, ip, MAX_IP_LEN - 1);
    r->resolved = true;
    
    pthread_mutex_unlock(&ctx->results_lock);
}

static void *worker_thread(void *arg) {
    brute_context_t *ctx = (brute_context_t *)arg;
    char subdomain[MAX_DOMAIN_LEN];
    char ip[MAX_IP_LEN];
    
    while (1) {
        pthread_mutex_lock(&ctx->index_lock);
        size_t idx = ctx->current_index++;
        pthread_mutex_unlock(&ctx->index_lock);
        
        if (idx >= ctx->wordlist->count) break;
        
        snprintf(subdomain, sizeof(subdomain), "%s.%s", 
                 ctx->wordlist->words[idx], ctx->config->domain);
        
        if (dns_resolve(subdomain, ip, sizeof(ip)) == 0) {
            if (ctx->wildcard_detected && strcmp(ip, ctx->wildcard_ip) == 0) {
                goto next;
            }
            add_result(ctx, subdomain, ip);
            if (ctx->config->verbose) {
                fprintf(stderr, "[+] %s -> %s\n", subdomain, ip);
            }
        }
        
next:
        __sync_fetch_and_add(&ctx->completed, 1);
        
        if (!ctx->config->verbose && ctx->completed % 100 == 0) {
            fprintf(stderr, "\rProgress: %zu/%zu", ctx->completed, ctx->wordlist->count);
        }
    }
    
    return NULL;
}

void output_results_json(brute_context_t *ctx, FILE *out) {
    fprintf(out, "[\n");
    for (size_t i = 0; i < ctx->results_count; i++) {
        fprintf(out, "  {\"subdomain\": \"%s\", \"ip\": \"%s\"}%s\n",
                ctx->results[i].subdomain,
                ctx->results[i].ip,
                (i < ctx->results_count - 1) ? "," : "");
    }
    fprintf(out, "]\n");
}

void output_results_text(brute_context_t *ctx, FILE *out) {
    for (size_t i = 0; i < ctx->results_count; i++) {
        fprintf(out, "%s\n", ctx->results[i].subdomain);
    }
}

int run_bruteforce(dns_config_t *config) {
    brute_context_t ctx = {0};
    ctx.config = config;
    ctx.wordlist = load_wordlist(config->wordlist_path);
    
    if (!ctx.wordlist) return 1;
    
    ctx.results_capacity = 1024;
    ctx.results = malloc(sizeof(dns_result_t) * ctx.results_capacity);
    ctx.results_count = 0;
    ctx.current_index = 0;
    ctx.completed = 0;
    
    pthread_mutex_init(&ctx.index_lock, NULL);
    pthread_mutex_init(&ctx.results_lock, NULL);
    
    if (config->detect_wildcard) {
        fprintf(stderr, "[*] Checking for wildcard DNS...\n");
        if (detect_wildcard(config->domain, ctx.wildcard_ip)) {
            ctx.wildcard_detected = true;
            fprintf(stderr, "[!] Wildcard detected: *.%s -> %s\n", 
                    config->domain, ctx.wildcard_ip);
        }
    }
    
    fprintf(stderr, "[*] Starting bruteforce with %d workers...\n", config->workers);
    fprintf(stderr, "[*] Wordlist: %zu entries\n", ctx.wordlist->count);
    
    pthread_t *threads = malloc(sizeof(pthread_t) * config->workers);
    
    for (int i = 0; i < config->workers; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &ctx);
    }
    
    for (int i = 0; i < config->workers; i++) {
        pthread_join(threads[i], NULL);
    }
    
    fprintf(stderr, "\n[*] Completed: %zu subdomains found\n", ctx.results_count);
    
    FILE *out = stdout;
    if (config->output_path) {
        out = fopen(config->output_path, "w");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file\n");
            out = stdout;
        }
    }
    
    if (config->json_output) {
        output_results_json(&ctx, out);
    } else {
        output_results_text(&ctx, out);
    }
    
    if (out != stdout) fclose(out);
    
    free(threads);
    free(ctx.results);
    free_wordlist(ctx.wordlist);
    pthread_mutex_destroy(&ctx.index_lock);
    pthread_mutex_destroy(&ctx.results_lock);
    
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s -d <domain> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -d, --domain <domain>     Target domain (required)\n");
    printf("  -w, --wordlist <file>     Wordlist file (optional, uses built-in)\n");
    printf("  -o, --output <file>       Output file (default: stdout)\n");
    printf("  -t, --threads <num>       Number of threads (default: %d)\n", DEFAULT_WORKERS);
    printf("  -j, --json                JSON output format\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  -W, --wildcard            Detect and skip wildcard domains\n");
    printf("  -h, --help                Show this help\n");
}

int main(int argc, char *argv[]) {
    dns_config_t config = {0};
    config.workers = DEFAULT_WORKERS;
    config.detect_wildcard = true;
    
    static struct option long_opts[] = {
        {"domain", required_argument, 0, 'd'},
        {"wordlist", required_argument, 0, 'w'},
        {"output", required_argument, 0, 'o'},
        {"threads", required_argument, 0, 't'},
        {"json", no_argument, 0, 'j'},
        {"verbose", no_argument, 0, 'v'},
        {"wildcard", no_argument, 0, 'W'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "d:w:o:t:jvWh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'd': config.domain = optarg; break;
            case 'w': config.wordlist_path = optarg; break;
            case 'o': config.output_path = optarg; break;
            case 't': config.workers = atoi(optarg); break;
            case 'j': config.json_output = true; break;
            case 'v': config.verbose = true; break;
            case 'W': config.detect_wildcard = true; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    if (!config.domain) {
        fprintf(stderr, "Error: Domain is required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (config.workers < 1) config.workers = 1;
    if (config.workers > MAX_WORKERS) config.workers = MAX_WORKERS;
    
    return run_bruteforce(&config);
}
