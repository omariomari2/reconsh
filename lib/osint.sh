#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

collect_osint() {
    local target="$1"
    local target_dir="$2"
    
    log_info "Starting OSINT collection for $target"
    
    local osint_dir="$target_dir/osint"
    mkdir -p "$osint_dir"
    
    collect_whois_data "$target" "$target_dir"
    collect_certificate_transparency "$target" "$osint_dir"
    collect_ip_information "$target" "$target_dir" "$osint_dir"
    collect_dns_history "$target" "$osint_dir"
    
    log_success "OSINT collection completed"
    
    return 0
}

collect_whois_data() {
    local target="$1"
    local target_dir="$2"
    local whois_file="$target_dir/whois.txt"
    
    log_info "Collecting WHOIS data..."
    
    if command_exists whois; then
        if whois "$target" > "$whois_file" 2>/dev/null; then
            log_success "WHOIS data saved to: $whois_file"
            
            extract_whois_json "$whois_file" "$target_dir/whois.json"
        else
            log_warn "WHOIS query failed for $target"
        fi
    else
        log_warn "whois command not available"
    fi
}

extract_whois_json() {
    local whois_file="$1"
    local json_file="$2"
    
    if [[ ! -f "$whois_file" ]]; then
        return 1
    fi
    
    local registrar creation_date expiry_date status nameservers
    
    registrar=$(grep -i "registrar:" "$whois_file" | head -1 | cut -d: -f2- | xargs)
    creation_date=$(grep -iE "(creation date|created|registered):" "$whois_file" | head -1 | cut -d: -f2- | xargs)
    expiry_date=$(grep -iE "(expir|expires):" "$whois_file" | head -1 | cut -d: -f2- | xargs)
    status=$(grep -i "status:" "$whois_file" | head -1 | cut -d: -f2- | xargs)
    
    local ns_array
    ns_array=$(grep -i "name server:" "$whois_file" | cut -d: -f2- | xargs -n1 | json_array)
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --arg registrar "${registrar:-}" \
        --arg creation_date "${creation_date:-}" \
        --arg expiry_date "${expiry_date:-}" \
        --arg status "${status:-}" \
        --argjson nameservers "${ns_array:-[]}" \
        '{
            timestamp: $timestamp,
            registrar: (if $registrar == "" then null else $registrar end),
            creation_date: (if $creation_date == "" then null else $creation_date end),
            expiry_date: (if $expiry_date == "" then null else $expiry_date end),
            status: (if $status == "" then null else $status end),
            nameservers: $nameservers
        }' > "$json_file"
}

collect_certificate_transparency() {
    local target="$1"
    local osint_dir="$2"
    local ct_file="$osint_dir/ct.json"
    local cache_dir
    cache_dir=$(create_cache_dir "$(dirname "$osint_dir")")
    
    log_info "Collecting certificate transparency data..."
    
    local url="https://crt.sh/?q=$target&output=json"
    
    if cached_curl "$url" "$cache_dir" > "$ct_file.tmp" 2>/dev/null; then
        if jq . "$ct_file.tmp" >/dev/null 2>&1; then
            jq '[.[] | {
                id: .id,
                logged_at: .logged_at,
                not_before: .not_before,
                not_after: .not_after,
                common_name: .common_name,
                matching_identities: .name_value,
                issuer_name: .issuer_name
            }] | sort_by(.logged_at) | reverse' "$ct_file.tmp" > "$ct_file"
            
            local cert_count
            cert_count=$(jq 'length' "$ct_file" 2>/dev/null || echo 0)
            log_success "Found $cert_count certificates in CT logs"
        else
            echo '[]' > "$ct_file"
            log_warn "Invalid CT data received"
        fi
        rm -f "$ct_file.tmp"
    else
        echo '[]' > "$ct_file"
        log_warn "Failed to query certificate transparency logs"
    fi
}

collect_ip_information() {
    local target="$1"
    local target_dir="$2"
    local osint_dir="$3"
    local dns_file="$target_dir/dns.json"
    local ip_info_file="$osint_dir/ipinfo.jsonl"
    
    log_info "Collecting IP information..."
    
    local ips_file="$target_dir/.osint_ips"
    > "$ips_file"
    
    if [[ -f "$dns_file" ]]; then
        jq -r '.[] | select(.type == "A") | .value' "$dns_file" 2>/dev/null | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >> "$ips_file"
    fi
    
    local target_ip
    target_ip=$(dig +short "$target" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [[ -n "$target_ip" ]]; then
        echo "$target_ip" >> "$ips_file"
    fi
    
    sort -u "$ips_file" -o "$ips_file"
    
    if [[ ! -s "$ips_file" ]]; then
        log_warn "No IP addresses found for information lookup"
        rm -f "$ips_file"
        return 1
    fi
    
    > "$ip_info_file"
    
    local cache_dir
    cache_dir=$(create_cache_dir "$target_dir")
    
    while IFS= read -r ip; do
        log_debug "Looking up IP information for: $ip"
        
        local url="https://ipinfo.io/$ip/json"
        
        if cached_curl "$url" "$cache_dir" 2>/dev/null | jq . >/dev/null 2>&1; then
            cached_curl "$url" "$cache_dir" 2>/dev/null | \
                jq --arg timestamp "$(timestamp)" '. + {timestamp: $timestamp}' >> "$ip_info_file"
        else
            jq -n \
                --arg ip "$ip" \
                --arg timestamp "$(timestamp)" \
                '{
                    ip: $ip,
                    timestamp: $timestamp,
                    error: "lookup_failed"
                }' >> "$ip_info_file"
        fi
        
        rate_limit 2 4
    done < "$ips_file"
    
    rm -f "$ips_file"
    
    local ip_count
    ip_count=$(wc -l < "$ip_info_file" 2>/dev/null || echo 0)
    log_success "Collected information for $ip_count IP addresses"
}

collect_dns_history() {
    local target="$1"
    local osint_dir="$2"
    local history_file="$osint_dir/dns_history.json"
    
    log_info "Collecting DNS history..."
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --arg target "$target" \
        '{
            timestamp: $timestamp,
            target: $target,
            note: "DNS history collection requires API integration",
            sources: ["securitytrails", "virustotal", "passivetotal"],
            data: []
        }' > "$history_file"
    
    log_info "DNS history placeholder created (requires API integration)"
}

collect_web_presence() {
    local target="$1"
    local osint_dir="$2"
    local presence_file="$osint_dir/web_presence.json"
    
    log_info "Checking web presence..."
    
    local social_platforms=("twitter.com" "facebook.com" "linkedin.com" "github.com" "instagram.com")
    local results=()
    
    for platform in "${social_platforms[@]}"; do
        local url="https://$platform/$target"
        local status_code
        
        status_code=$(curl -s -o /dev/null -w "%{http_code}" \
                          --max-time 10 \
                          --user-agent "reconsh/1.0 (Security Research)" \
                          "$url" 2>/dev/null)
        
        if [[ "$status_code" == "200" ]]; then
            results+=("{\"platform\": \"$platform\", \"url\": \"$url\", \"status\": \"found\"}")
        fi
        
        rate_limit 1 2
    done
    
    local results_json="[]"
    if [[ ${#results[@]} -gt 0 ]]; then
        results_json=$(printf '%s\n' "${results[@]}" | jq -s .)
    fi
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --arg target "$target" \
        --argjson results "$results_json" \
        '{
            timestamp: $timestamp,
            target: $target,
            web_presence: $results
        }' > "$presence_file"
    
    local found_count
    found_count=$(echo "$results_json" | jq 'length')
    log_info "Found $found_count social media profiles"
}

generate_osint_summary() {
    local target="$1"
    local osint_dir="$2"
    local summary_file="$osint_dir/summary.json"
    
    log_info "Generating OSINT summary..."
    
    local whois_data ct_data ip_data
    whois_data=$(cat "$osint_dir/../whois.json" 2>/dev/null || echo 'null')
    ct_data=$(cat "$osint_dir/ct.json" 2>/dev/null || echo '[]')
    ip_data=$(jq -s . "$osint_dir/ipinfo.jsonl" 2>/dev/null || echo '[]')
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --arg target "$target" \
        --argjson whois "$whois_data" \
        --argjson certificates "$ct_data" \
        --argjson ip_information "$ip_data" \
        '{
            timestamp: $timestamp,
            target: $target,
            whois: $whois,
            certificate_transparency: {
                total_certificates: ($certificates | length),
                latest_certificates: ($certificates | .[0:5])
            },
            ip_information: {
                total_ips: ($ip_information | length),
                unique_asns: ($ip_information | [.[].org // empty] | unique | length),
                countries: ($ip_information | [.[].country // empty] | unique)
            }
        }' > "$summary_file"
    
    log_success "OSINT summary saved to: $summary_file"
}
