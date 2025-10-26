#!/bin/bash
#
# scan.sh - Port scanning module using nmap
#

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Port scanning with nmap
scan_ports() {
    local target="$1"
    local target_dir="$2"
    local subdomains_file="$target_dir/subdomains.txt"
    local dns_file="$target_dir/dns.json"
    
    log_info "Starting port scanning for $target"
    
    # Collect IP addresses to scan
    local ips_file="$target_dir/.scan_ips"
    collect_scan_targets "$target" "$subdomains_file" "$dns_file" "$ips_file"
    
    if [[ ! -s "$ips_file" ]]; then
        log_warn "No IP addresses found for scanning"
        return 1
    fi
    
    local ip_count
    ip_count=$(wc -l < "$ips_file")
    log_info "Scanning $ip_count unique IP addresses"
    
    # Perform nmap scan
    perform_nmap_scan "$ips_file" "$target_dir"
    
    # Process results
    process_nmap_results "$target_dir"
    
    # Cleanup
    rm -f "$ips_file"
    
    log_success "Port scanning completed"
    
    return 0
}

# Collect IP addresses for scanning
collect_scan_targets() {
    local target="$1"
    local subdomains_file="$2"
    local dns_file="$3"
    local output_file="$4"
    
    > "$output_file"
    
    # Get IPs from DNS enumeration results
    if [[ -f "$dns_file" ]]; then
        jq -r '.[] | select(.type == "A") | .value' "$dns_file" 2>/dev/null | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >> "$output_file"
    fi
    
    # Resolve target domain directly if not in DNS results
    local target_ip
    target_ip=$(dig +short "$target" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [[ -n "$target_ip" ]]; then
        echo "$target_ip" >> "$output_file"
    fi
    
    # Resolve subdomains if DNS file doesn't exist
    if [[ ! -f "$dns_file" && -f "$subdomains_file" ]]; then
        log_info "Resolving subdomain IPs for scanning..."
        while IFS= read -r subdomain; do
            local ip
            ip=$(dig +short "$subdomain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
            if [[ -n "$ip" ]]; then
                echo "$ip" >> "$output_file"
            fi
        done < "$subdomains_file"
    fi
    
    # Remove duplicates and private IPs (optional - comment out to scan private ranges)
    sort -u "$output_file" | \
        grep -v -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)' > "$output_file.tmp" && \
        mv "$output_file.tmp" "$output_file"
    
    # If no public IPs found, include private IPs
    if [[ ! -s "$output_file" ]]; then
        log_warn "No public IPs found, including private ranges"
        sort -u "$output_file.orig" > "$output_file" 2>/dev/null || true
    fi
}

# Perform nmap scan
perform_nmap_scan() {
    local ips_file="$1"
    local target_dir="$2"
    local nmap_output="$target_dir/nmap"
    
    # Prepare nmap command
    local nmap_cmd="nmap"
    local nmap_args=()
    
    # Basic arguments
    nmap_args+=("-n")  # No DNS resolution
    nmap_args+=("-T4") # Aggressive timing
    nmap_args+=("-oG" "$nmap_output.gnmap")  # Greppable output
    nmap_args+=("-oN" "$nmap_output.nmap")   # Normal output
    
    # Port selection
    if [[ "${FAST_MODE:-false}" == "true" ]]; then
        log_info "Fast mode: scanning top 100 ports"
        nmap_args+=("-F")  # Fast scan (top 100 ports)
    else
        log_info "Full mode: scanning top 1000 ports with service detection"
        nmap_args+=("--top-ports" "1000")
        nmap_args+=("-sV")  # Service version detection
    fi
    
    # Add IP addresses from file
    nmap_args+=("-iL" "$ips_file")
    
    log_info "Running nmap scan..."
    log_debug "Command: $nmap_cmd ${nmap_args[*]}"
    
    # Execute nmap scan
    if ! timeout $((MODULE_TIMEOUT * 2)) "$nmap_cmd" "${nmap_args[@]}" 2>/dev/null; then
        log_error "Nmap scan failed or timed out"
        return 1
    fi
    
    log_success "Nmap scan completed"
}

# Process nmap results into JSON format
process_nmap_results() {
    local target_dir="$1"
    local gnmap_file="$target_dir/nmap.gnmap"
    local json_file="$target_dir/nmap.json"
    
    if [[ ! -f "$gnmap_file" ]]; then
        log_error "Nmap greppable output not found"
        return 1
    fi
    
    log_info "Processing nmap results..."
    
    # Parse greppable output and convert to JSON
    awk '
    BEGIN {
        print "["
        first = 1
    }
    
    /^Host:/ && /Ports:/ {
        # Extract IP address
        ip = $2
        
        # Extract status
        status = $3
        gsub(/[()]/, "", status)
        
        # Extract ports section
        ports_start = index($0, "Ports: ") + 7
        ports_section = substr($0, ports_start)
        
        # Remove trailing info
        gsub(/\t.*$/, "", ports_section)
        
        # Split ports by comma
        split(ports_section, port_entries, ", ")
        
        for (i in port_entries) {
            if (port_entries[i] == "") continue
            
            # Parse port entry: port/state/protocol/owner/service/rpc/version
            split(port_entries[i], port_parts, "/")
            
            if (length(port_parts) >= 3) {
                port = port_parts[1]
                state = port_parts[2]
                protocol = port_parts[3]
                service = (length(port_parts) >= 5) ? port_parts[5] : ""
                version = (length(port_parts) >= 7) ? port_parts[7] : ""
                
                # Only include open ports
                if (state == "open") {
                    if (!first) print ","
                    first = 0
                    
                    printf "    {\n"
                    printf "      \"ip\": \"%s\",\n", ip
                    printf "      \"port\": %s,\n", port
                    printf "      \"protocol\": \"%s\",\n", protocol
                    printf "      \"state\": \"%s\",\n", state
                    printf "      \"service\": \"%s\",\n", service
                    printf "      \"version\": \"%s\",\n", version
                    printf "      \"timestamp\": \"%s\"\n", strftime("%Y-%m-%dT%H:%M:%SZ", systime())
                    printf "    }"
                }
            }
        }
    }
    
    END {
        print "\n]"
    }
    ' "$gnmap_file" > "$json_file"
    
    # Validate JSON
    if ! jq . "$json_file" >/dev/null 2>&1; then
        log_error "Generated invalid JSON, creating empty array"
        echo '[]' > "$json_file"
    fi
    
    local open_ports
    open_ports=$(jq 'length' "$json_file" 2>/dev/null || echo 0)
    log_success "Found $open_ports open ports"
    log_info "Results saved to: $json_file"
}

# Generate port scan statistics
generate_scan_stats() {
    local scan_file="$1"
    local target_dir="$2"
    local stats_file="$target_dir/scan_stats.json"
    
    if [[ ! -f "$scan_file" ]]; then
        return 1
    fi
    
    local total_ports
    total_ports=$(jq 'length' "$scan_file")
    
    local port_counts
    port_counts=$(jq '[group_by(.port)[] | {port: .[0].port, count: length}] | sort_by(.count) | reverse' "$scan_file")
    
    local service_counts
    service_counts=$(jq '[group_by(.service)[] | {service: .[0].service, count: length}] | sort_by(.count) | reverse' "$scan_file")
    
    local ip_counts
    ip_counts=$(jq '[group_by(.ip)[] | {ip: .[0].ip, open_ports: length}] | sort_by(.open_ports) | reverse' "$scan_file")
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --argjson total "$total_ports" \
        --argjson by_port "$port_counts" \
        --argjson by_service "$service_counts" \
        --argjson by_ip "$ip_counts" \
        '{
            timestamp: $timestamp,
            total_open_ports: $total,
            ports_by_frequency: $by_port,
            services_by_frequency: $by_service,
            ips_by_open_ports: $by_ip
        }' > "$stats_file"
    
    log_debug "Port scan statistics saved to: $stats_file"
}

# Quick port check for specific services
quick_service_check() {
    local target="$1"
    local target_dir="$2"
    local common_ports=("21" "22" "23" "25" "53" "80" "110" "143" "443" "993" "995" "8080" "8443")
    
    log_info "Quick service check for common ports..."
    
    local results_file="$target_dir/quick_scan.json"
    local temp_results="$target_dir/.quick_scan_temp"
    
    > "$temp_results"
    
    for port in "${common_ports[@]}"; do
        if timeout 5 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
            jq -n \
                --arg ip "$target" \
                --arg port "$port" \
                --arg timestamp "$(timestamp)" \
                '{
                    ip: $ip,
                    port: ($port | tonumber),
                    state: "open",
                    method: "tcp_connect",
                    timestamp: $timestamp
                }' >> "$temp_results"
        fi
    done
    
    jq -s . "$temp_results" > "$results_file"
    rm -f "$temp_results"
    
    local open_count
    open_count=$(jq 'length' "$results_file")
    log_info "Quick scan found $open_count open ports"
}
