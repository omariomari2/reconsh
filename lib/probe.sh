#!/bin/bash
#
# probe.sh - HTTP/HTTPS probing module
#

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# HTTP probing with technology detection
probe_http() {
    local target="$1"
    local target_dir="$2"
    local output_file="$target_dir/probe.jsonl"
    local subdomains_file="$target_dir/subdomains.txt"
    local threads="${THREADS:-10}"
    
    log_info "Starting HTTP probing for $target"
    
    # Create list of hosts to probe
    local hosts_file="$target_dir/.probe_hosts"
    if [[ -f "$subdomains_file" ]]; then
        cat "$subdomains_file" > "$hosts_file"
    else
        echo "$target" > "$hosts_file"
    fi
    
    # Add root domain if not present
    if ! grep -q "^$target$" "$hosts_file"; then
        echo "$target" >> "$hosts_file"
    fi
    
    local total_hosts
    total_hosts=$(wc -l < "$hosts_file")
    log_info "Probing $total_hosts hosts for HTTP/HTTPS services"
    
    # Clear output file
    > "$output_file"
    
    # Probe hosts in parallel
    local current=0
    while IFS= read -r host; do
        ((current++))
        show_progress "$current" "$total_hosts" "hosts"
        
        # Probe both HTTP and HTTPS
        probe_host_http "$host" >> "$output_file" &
        probe_host_https "$host" >> "$output_file" &
        
        # Limit concurrent jobs
        if (( current % (threads / 2) == 0 )); then
            wait
        fi
    done < "$hosts_file"
    
    wait
    clear_progress
    
    # Remove empty lines and sort by host
    grep -v '^$' "$output_file" | sort > "$output_file.tmp" && mv "$output_file.tmp" "$output_file"
    
    # Cleanup
    rm -f "$hosts_file"
    
    local probe_count
    probe_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    log_success "HTTP probing completed - $probe_count responses"
    log_info "Results saved to: $output_file"
    
    return 0
}

# Probe single host for HTTP
probe_host_http() {
    local host="$1"
    local url="http://$host"
    probe_url "$url" "$host" "http"
}

# Probe single host for HTTPS
probe_host_https() {
    local host="$1"
    local url="https://$host"
    probe_url "$url" "$host" "https"
}

# Probe a specific URL
probe_url() {
    local url="$1"
    local host="$2"
    local scheme="$3"
    local timeout="${MODULE_TIMEOUT:-30}"
    
    local temp_headers temp_body
    temp_headers=$(mktemp)
    temp_body=$(mktemp)
    
    # Perform HTTP request with headers and body capture
    local status_code final_url
    if curl -s -L \
            --max-time "$timeout" \
            --max-redirs 5 \
            --user-agent "reconsh/1.0 (Security Research)" \
            --connect-timeout 10 \
            -w "%{http_code}|%{url_effective}" \
            -D "$temp_headers" \
            -o "$temp_body" \
            "$url" 2>/dev/null; then
        
        local curl_output
        curl_output=$(curl -s -L \
                           --max-time "$timeout" \
                           --max-redirs 5 \
                           --user-agent "reconsh/1.0 (Security Research)" \
                           --connect-timeout 10 \
                           -w "%{http_code}|%{url_effective}" \
                           -D "$temp_headers" \
                           -o "$temp_body" \
                           "$url" 2>/dev/null)
        
        status_code=$(echo "$curl_output" | cut -d'|' -f1)
        final_url=$(echo "$curl_output" | cut -d'|' -f2)
        
        # Only process successful responses
        if [[ "$status_code" =~ ^[1-5][0-9][0-9]$ ]]; then
            process_http_response "$host" "$scheme" "$url" "$final_url" "$status_code" "$temp_headers" "$temp_body"
        fi
    fi
    
    # Cleanup
    rm -f "$temp_headers" "$temp_body"
}

# Process HTTP response and extract information
process_http_response() {
    local host="$1"
    local scheme="$2"
    local original_url="$3"
    local final_url="$4"
    local status_code="$5"
    local headers_file="$6"
    local body_file="$7"
    
    # Extract headers
    local server content_type content_length x_powered_by location
    server=$(grep -i '^server:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
    content_type=$(grep -i '^content-type:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
    content_length=$(grep -i '^content-length:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
    x_powered_by=$(grep -i '^x-powered-by:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
    location=$(grep -i '^location:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
    
    # Extract title from HTML
    local title
    if [[ -f "$body_file" ]]; then
        title=$(grep -i '<title>' "$body_file" | sed -e 's/<[^>]*>//g' | tr -d '\r\n' | head -1 | xargs)
        # Limit title length
        if [[ ${#title} -gt 100 ]]; then
            title="${title:0:97}..."
        fi
    fi
    
    # Get actual content length
    local actual_length=0
    if [[ -f "$body_file" ]]; then
        actual_length=$(wc -c < "$body_file" 2>/dev/null || echo 0)
    fi
    
    # Detect technologies
    local technologies
    technologies=$(detect_technologies "$headers_file" "$body_file")
    
    # Create JSON response
    jq -n \
        --arg timestamp "$(timestamp)" \
        --arg host "$host" \
        --arg scheme "$scheme" \
        --arg original_url "$original_url" \
        --arg final_url "$final_url" \
        --arg status_code "$status_code" \
        --arg server "${server:-}" \
        --arg content_type "${content_type:-}" \
        --arg content_length "${content_length:-}" \
        --arg actual_length "$actual_length" \
        --arg x_powered_by "${x_powered_by:-}" \
        --arg location "${location:-}" \
        --arg title "${title:-}" \
        --argjson technologies "$technologies" \
        '{
            timestamp: $timestamp,
            host: $host,
            scheme: $scheme,
            original_url: $original_url,
            final_url: $final_url,
            status_code: ($status_code | tonumber),
            server: (if $server == "" then null else $server end),
            content_type: (if $content_type == "" then null else $content_type end),
            content_length: (if $content_length == "" then null else ($content_length | tonumber) end),
            actual_length: ($actual_length | tonumber),
            x_powered_by: (if $x_powered_by == "" then null else $x_powered_by end),
            location: (if $location == "" then null else $location end),
            title: (if $title == "" then null else $title end),
            technologies: $technologies
        }'
}

# Detect web technologies from headers and body
detect_technologies() {
    local headers_file="$1"
    local body_file="$2"
    local technologies=()
    
    # Check headers for technology indicators
    if [[ -f "$headers_file" ]]; then
        # Server header analysis
        local server_header
        server_header=$(grep -i '^server:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
        if [[ -n "$server_header" ]]; then
            case "$server_header" in
                *nginx*) technologies+=("nginx") ;;
                *apache*) technologies+=("Apache") ;;
                *IIS*) technologies+=("IIS") ;;
                *cloudflare*) technologies+=("Cloudflare") ;;
            esac
        fi
        
        # X-Powered-By header
        local powered_by
        powered_by=$(grep -i '^x-powered-by:' "$headers_file" | cut -d' ' -f2- | tr -d '\r\n' | head -1)
        if [[ -n "$powered_by" ]]; then
            case "$powered_by" in
                *PHP*) technologies+=("PHP") ;;
                *ASP.NET*) technologies+=("ASP.NET") ;;
                *Express*) technologies+=("Express.js") ;;
            esac
        fi
        
        # Other headers
        if grep -qi '^x-drupal-cache:' "$headers_file"; then
            technologies+=("Drupal")
        fi
        if grep -qi '^x-generator:.*wordpress' "$headers_file"; then
            technologies+=("WordPress")
        fi
    fi
    
    # Check body for technology indicators (limited to avoid large file processing)
    if [[ -f "$body_file" ]] && ! is_file_too_large "$body_file" 1; then
        # WordPress detection
        if grep -qi 'wp-content\|wp-includes\|wordpress' "$body_file"; then
            technologies+=("WordPress")
        fi
        
        # Drupal detection
        if grep -qi 'drupal\|sites/default/files' "$body_file"; then
            technologies+=("Drupal")
        fi
        
        # Joomla detection
        if grep -qi 'joomla\|/components/com_' "$body_file"; then
            technologies+=("Joomla")
        fi
        
        # Framework detection
        if grep -qi 'react\|reactjs' "$body_file"; then
            technologies+=("React")
        fi
        if grep -qi 'angular\|angularjs' "$body_file"; then
            technologies+=("Angular")
        fi
        if grep -qi 'vue\.js\|vuejs' "$body_file"; then
            technologies+=("Vue.js")
        fi
        if grep -qi 'bootstrap' "$body_file"; then
            technologies+=("Bootstrap")
        fi
        if grep -qi 'jquery' "$body_file"; then
            technologies+=("jQuery")
        fi
    fi
    
    # Remove duplicates and convert to JSON array
    printf '%s\n' "${technologies[@]}" | sort -u | json_array
}

# Generate HTTP probing statistics
generate_probe_stats() {
    local probe_file="$1"
    local target_dir="$2"
    local stats_file="$target_dir/probe_stats.json"
    
    if [[ ! -f "$probe_file" ]]; then
        return 1
    fi
    
    local total_responses
    total_responses=$(wc -l < "$probe_file")
    
    local status_counts
    status_counts=$(jq -s '[group_by(.status_code)[] | {status: .[0].status_code, count: length}]' "$probe_file")
    
    local scheme_counts
    scheme_counts=$(jq -s '[group_by(.scheme)[] | {scheme: .[0].scheme, count: length}]' "$probe_file")
    
    local tech_counts
    tech_counts=$(jq -s '[.[].technologies[] // empty] | group_by(.) | map({technology: .[0], count: length}) | sort_by(.count) | reverse' "$probe_file")
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --argjson total "$total_responses" \
        --argjson by_status "$status_counts" \
        --argjson by_scheme "$scheme_counts" \
        --argjson technologies "$tech_counts" \
        '{
            timestamp: $timestamp,
            total_responses: $total,
            responses_by_status: $by_status,
            responses_by_scheme: $by_scheme,
            technologies_detected: $technologies
        }' > "$stats_file"
    
    log_debug "HTTP probe statistics saved to: $stats_file"
}
