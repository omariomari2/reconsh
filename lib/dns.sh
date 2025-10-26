#!/bin/bash
#
# dns.sh - DNS enumeration module
#

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# DNS record types to query
DNS_RECORD_TYPES=("A" "AAAA" "CNAME" "MX" "NS" "TXT" "SOA")

# Enumerate DNS records for target and subdomains
enumerate_dns() {
    local target="$1"
    local target_dir="$2"
    local output_file="$target_dir/dns.json"
    local subdomains_file="$target_dir/subdomains.txt"
    local threads="${THREADS:-10}"
    
    log_info "Starting DNS enumeration for $target"
    
    # Create list of domains to query
    local domains_file="$target_dir/.dns_targets"
    if [[ -f "$subdomains_file" ]]; then
        cat "$subdomains_file" > "$domains_file"
    else
        echo "$target" > "$domains_file"
    fi
    
    # Add root domain if not present
    if ! grep -q "^$target$" "$domains_file"; then
        echo "$target" >> "$domains_file"
    fi
    
    local total_domains
    total_domains=$(wc -l < "$domains_file")
    log_info "Querying DNS records for $total_domains domains"
    
    # Query DNS records in parallel
    local temp_results="$target_dir/.dns_results"
    > "$temp_results"
    
    local current=0
    while IFS= read -r domain; do
        ((current++))
        show_progress "$current" "$total_domains" "domains"
        
        query_domain_dns "$domain" >> "$temp_results" &
        
        # Limit concurrent jobs
        if (( current % threads == 0 )); then
            wait
        fi
    done < "$domains_file"
    
    wait
    clear_progress
    
    # Convert results to JSON
    log_info "Processing DNS results..."
    process_dns_results "$temp_results" "$output_file"
    
    # Attempt zone transfers
    attempt_zone_transfers "$target" "$target_dir"
    
    # Cleanup
    rm -f "$domains_file" "$temp_results"
    
    log_success "DNS enumeration completed"
    log_info "Results saved to: $output_file"
    
    return 0
}

# Query DNS records for a single domain
query_domain_dns() {
    local domain="$1"
    local timestamp
    timestamp=$(timestamp)
    
    for record_type in "${DNS_RECORD_TYPES[@]}"; do
        local result
        result=$(dig +short "$domain" "$record_type" 2>/dev/null | grep -v '^$')
        
        if [[ -n "$result" ]]; then
            while IFS= read -r record; do
                # Clean up the record
                record=$(echo "$record" | tr -d '\r' | xargs)
                if [[ -n "$record" ]]; then
                    printf '%s\t%s\t%s\t%s\n' "$domain" "$record_type" "$record" "$timestamp"
                fi
            done <<< "$result"
        fi
    done
}

# Process DNS results into structured JSON
process_dns_results() {
    local temp_results="$1"
    local output_file="$2"
    
    if [[ ! -s "$temp_results" ]]; then
        echo '[]' > "$output_file"
        return 0
    fi
    
    # Convert tab-separated results to JSON
    awk -F'\t' '
    {
        domain = $1
        type = $2
        value = $3
        timestamp = $4
        
        # Escape quotes in value
        gsub(/"/, "\\\"", value)
        
        printf "{\"domain\":\"%s\",\"type\":\"%s\",\"value\":\"%s\",\"timestamp\":\"%s\"}\n", 
               domain, type, value, timestamp
    }' "$temp_results" | jq -s . > "$output_file"
}

# Attempt zone transfers on discovered name servers
attempt_zone_transfers() {
    local target="$1"
    local target_dir="$2"
    local dns_file="$target_dir/dns.json"
    local axfr_file="$target_dir/zone_transfers.txt"
    
    log_info "Attempting zone transfers..."
    
    if [[ ! -f "$dns_file" ]]; then
        log_warn "DNS file not found, skipping zone transfers"
        return 1
    fi
    
    # Extract NS records
    local nameservers
    nameservers=$(jq -r '.[] | select(.type == "NS") | .value' "$dns_file" 2>/dev/null | sort -u)
    
    if [[ -z "$nameservers" ]]; then
        log_warn "No nameservers found for zone transfer attempts"
        return 1
    fi
    
    > "$axfr_file"
    
    while IFS= read -r ns; do
        if [[ -n "$ns" ]]; then
            log_debug "Attempting zone transfer from: $ns"
            
            # Remove trailing dot if present
            ns=${ns%.}
            
            local axfr_result
            if axfr_result=$(dig @"$ns" "$target" AXFR +time=10 2>/dev/null); then
                if echo "$axfr_result" | grep -q "XFR size"; then
                    log_success "Zone transfer successful from: $ns"
                    echo "=== Zone transfer from $ns ===" >> "$axfr_file"
                    echo "$axfr_result" >> "$axfr_file"
                    echo "" >> "$axfr_file"
                else
                    log_debug "Zone transfer denied by: $ns"
                fi
            else
                log_debug "Zone transfer failed for: $ns"
            fi
        fi
    done <<< "$nameservers"
    
    if [[ -s "$axfr_file" ]]; then
        log_success "Zone transfer results saved to: $axfr_file"
    else
        log_info "No successful zone transfers"
        rm -f "$axfr_file"
    fi
}

# Resolve IP addresses for domains
resolve_ips() {
    local domains_file="$1"
    local output_file="$2"
    local threads="${THREADS:-10}"
    
    log_info "Resolving IP addresses..."
    
    # Function to resolve a single domain
    resolve_domain() {
        local domain="$1"
        local ipv4 ipv6
        
        ipv4=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        ipv6=$(dig +short "$domain" AAAA 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' | head -1)
        
        if [[ -n "$ipv4" || -n "$ipv6" ]]; then
            jq -n \
                --arg domain "$domain" \
                --arg ipv4 "${ipv4:-}" \
                --arg ipv6 "${ipv6:-}" \
                --arg timestamp "$(timestamp)" \
                '{
                    domain: $domain,
                    ipv4: (if $ipv4 == "" then null else $ipv4 end),
                    ipv6: (if $ipv6 == "" then null else $ipv6 end),
                    timestamp: $timestamp
                }'
        fi
    }
    export -f resolve_domain
    
    # Parallel resolution
    cat "$domains_file" | \
        parallel_exec "$threads" 'resolve_domain {}' | \
        jq -s . > "$output_file"
}

# Generate DNS statistics
generate_dns_stats() {
    local dns_file="$1"
    local target_dir="$2"
    local stats_file="$target_dir/dns_stats.json"
    
    if [[ ! -f "$dns_file" ]]; then
        return 1
    fi
    
    local record_counts
    record_counts=$(jq '[group_by(.type)[] | {type: .[0].type, count: length}]' "$dns_file")
    
    local total_records
    total_records=$(jq 'length' "$dns_file")
    
    local unique_domains
    unique_domains=$(jq '[.[].domain] | unique | length' "$dns_file")
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --argjson total "$total_records" \
        --argjson domains "$unique_domains" \
        --argjson by_type "$record_counts" \
        '{
            timestamp: $timestamp,
            total_records: $total,
            unique_domains: $domains,
            records_by_type: $by_type
        }' > "$stats_file"
    
    log_debug "DNS statistics saved to: $stats_file"
}
