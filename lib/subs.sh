#!/bin/bash
#
# subs.sh - Subdomain enumeration module
#

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Enumerate subdomains using passive sources
enumerate_subdomains() {
    local target="$1"
    local target_dir="$2"
    local output_file="$target_dir/subdomains.txt"
    local cache_dir
    cache_dir=$(create_cache_dir "$target_dir")
    
    log_info "Starting subdomain enumeration for $target"
    
    # Validate domain
    if ! is_valid_domain "$target"; then
        log_error "Invalid domain format: $target"
        return 1
    fi
    
    # Collect subdomains from multiple sources
    local temp_subs="$target_dir/.subdomains_temp"
    > "$temp_subs"
    
    # Add the root domain
    echo "$target" >> "$temp_subs"
    
    # Source 1: crt.sh Certificate Transparency
    log_info "Querying crt.sh for certificate transparency data..."
    query_crtsh "$target" "$cache_dir" >> "$temp_subs" || log_warn "crt.sh query failed"
    
    rate_limit 1 2
    
    # Source 2: BufferOver DNS
    log_info "Querying BufferOver for DNS data..."
    query_bufferover "$target" "$cache_dir" >> "$temp_subs" || log_warn "BufferOver query failed"
    
    # Process and clean results
    log_info "Processing and deduplicating results..."
    process_subdomains "$target" "$temp_subs" "$output_file"
    
    # Cleanup
    rm -f "$temp_subs"
    
    local count
    count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    log_success "Found $count subdomains for $target"
    log_info "Results saved to: $output_file"
    
    return 0
}

# Query crt.sh for certificate transparency data
query_crtsh() {
    local domain="$1"
    local cache_dir="$2"
    local url="https://crt.sh/?q=%25.$domain&output=json"
    
    log_debug "Querying crt.sh: $url"
    
    if ! cached_curl "$url" "$cache_dir"; then
        return 1
    fi | jq -r '.[].name_value' 2>/dev/null | \
        tr '\n' '\0' | xargs -0 -n1 echo | \
        grep -v '^$' | \
        sed 's/^\*\.//g' | \
        sort -u
}

# Query BufferOver for DNS data
query_bufferover() {
    local domain="$1"
    local cache_dir="$2"
    local url="https://dns.bufferover.run/dns?q=.$domain"
    
    log_debug "Querying BufferOver: $url"
    
    if ! cached_curl "$url" "$cache_dir"; then
        return 1
    fi | jq -r '.FDNS_A[]?, .RDNS[]?' 2>/dev/null | \
        cut -d',' -f2 | \
        grep -v '^$' | \
        sort -u
}

# Process and filter subdomains
process_subdomains() {
    local root_domain="$1"
    local temp_file="$2"
    local output_file="$3"
    
    # Clean, deduplicate, and filter subdomains
    cat "$temp_file" | \
        # Remove empty lines and whitespace
        sed '/^\s*$/d' | \
        tr -d '\r' | \
        # Convert to lowercase
        tr '[:upper:]' '[:lower:]' | \
        # Remove wildcards and invalid characters
        sed 's/^\*\.//g' | \
        grep -E '^[a-zA-Z0-9.-]+$' | \
        # Filter only subdomains of target
        grep -E "(^|\.)$root_domain$" | \
        # Remove duplicates and sort
        sort -u | \
        # Filter out common wildcards and invalid entries
        grep -v -E '^(\*|_|\.|-)' | \
        grep -v -E '(\*|\s)' > "$output_file"
    
    # Add common subdomains to check if not already present
    local common_subs=("www" "mail" "ftp" "admin" "api" "dev" "test" "staging" "blog")
    for sub in "${common_subs[@]}"; do
        local full_sub="$sub.$root_domain"
        if ! grep -q "^$full_sub$" "$output_file"; then
            echo "$full_sub" >> "$output_file"
        fi
    done
    
    # Final sort and dedupe
    sort -u "$output_file" -o "$output_file"
}

# Verify subdomains by attempting DNS resolution
verify_subdomains() {
    local input_file="$1"
    local output_file="$2"
    local threads="${THREADS:-10}"
    
    log_info "Verifying subdomains with DNS resolution..."
    
    # Function to check if subdomain resolves
    check_subdomain() {
        local subdomain="$1"
        if dig +short "$subdomain" A 2>/dev/null | grep -q '^[0-9]'; then
            echo "$subdomain"
        fi
    }
    export -f check_subdomain
    
    # Parallel verification
    cat "$input_file" | \
        parallel_exec "$threads" 'check_subdomain {}' > "$output_file"
    
    local verified_count
    verified_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    log_info "Verified $verified_count subdomains"
}

# Generate subdomain statistics
generate_subdomain_stats() {
    local subdomains_file="$1"
    local target_dir="$2"
    local stats_file="$target_dir/subdomain_stats.json"
    
    if [[ ! -f "$subdomains_file" ]]; then
        return 1
    fi
    
    local total_count
    total_count=$(wc -l < "$subdomains_file")
    
    local depth_stats
    depth_stats=$(awk -F. '{print NF-1}' "$subdomains_file" | sort -n | uniq -c | \
        jq -R 'split(" ") | {depth: (.[1] | tonumber), count: (.[0] | tonumber)}' | \
        jq -s .)
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --argjson total "$total_count" \
        --argjson depth_distribution "$depth_stats" \
        '{
            timestamp: $timestamp,
            total_subdomains: $total,
            depth_distribution: $depth_distribution
        }' > "$stats_file"
    
    log_debug "Subdomain statistics saved to: $stats_file"
}
