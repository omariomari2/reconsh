#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

create_summary() {
    local target="$1"
    local target_dir="$2"
    local summary_file="$target_dir/summary.json"
    
    log_info "Generating comprehensive summary for $target"
    
    local subdomains_data dns_data probe_data scan_data osint_data
    
    subdomains_data=$(collect_subdomain_summary "$target_dir")
    dns_data=$(collect_dns_summary "$target_dir")
    probe_data=$(collect_probe_summary "$target_dir")
    scan_data=$(collect_scan_summary "$target_dir")
    osint_data=$(collect_osint_summary "$target_dir")
    
    local exec_summary
    exec_summary=$(generate_executive_summary "$target" "$target_dir")
    
    jq -n \
        --arg timestamp "$(timestamp)" \
        --arg target "$target" \
        --arg version "1.0" \
        --argjson executive_summary "$exec_summary" \
        --argjson subdomains "$subdomains_data" \
        --argjson dns "$dns_data" \
        --argjson http_probing "$probe_data" \
        --argjson port_scanning "$scan_data" \
        --argjson osint "$osint_data" \
        '{
            reconsh_version: $version,
            timestamp: $timestamp,
            target: $target,
            executive_summary: $executive_summary,
            modules: {
                subdomains: $subdomains,
                dns: $dns,
                http_probing: $http_probing,
                port_scanning: $port_scanning,
                osint: $osint
            }
        }' > "$summary_file"
    
    log_success "Summary generated: $summary_file"
    
    generate_text_report "$target" "$target_dir"
    
    return 0
}

collect_subdomain_summary() {
    local target_dir="$1"
    local subdomains_file="$target_dir/subdomains.txt"
    
    if [[ ! -f "$subdomains_file" ]]; then
        echo 'null'
        return
    fi
    
    local total_count depth_stats
    total_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
    
    depth_stats=$(awk -F. '{print NF-1}' "$subdomains_file" 2>/dev/null | \
        sort -n | uniq -c | \
        awk '{printf "{\"depth\":%d,\"count\":%d}\n", $2, $1}' | \
        jq -s . 2>/dev/null || echo '[]')
    
    jq -n \
        --argjson total "$total_count" \
        --argjson depth_distribution "$depth_stats" \
        '{
            total_subdomains: $total,
            depth_distribution: $depth_distribution,
            status: (if $total > 0 then "completed" else "no_results" end)
        }'
}

collect_dns_summary() {
    local target_dir="$1"
    local dns_file="$target_dir/dns.json"
    
    if [[ ! -f "$dns_file" ]]; then
        echo 'null'
        return
    fi
    
    local total_records record_types unique_domains
    total_records=$(jq 'length' "$dns_file" 2>/dev/null || echo 0)
    unique_domains=$(jq '[.[].domain] | unique | length' "$dns_file" 2>/dev/null || echo 0)
    record_types=$(jq '[group_by(.type)[] | {type: .[0].type, count: length}]' "$dns_file" 2>/dev/null || echo '[]')
    
    jq -n \
        --argjson total "$total_records" \
        --argjson domains "$unique_domains" \
        --argjson by_type "$record_types" \
        '{
            total_records: $total,
            unique_domains: $domains,
            records_by_type: $by_type,
            status: (if $total > 0 then "completed" else "no_results" end)
        }'
}

collect_probe_summary() {
    local target_dir="$1"
    local probe_file="$target_dir/probe.jsonl"
    
    if [[ ! -f "$probe_file" ]]; then
        echo 'null'
        return
    fi
    
    local total_responses status_counts tech_counts live_hosts
    total_responses=$(wc -l < "$probe_file" 2>/dev/null || echo 0)
    
    if [[ "$total_responses" -eq 0 ]]; then
        echo 'null'
        return
    fi
    
    status_counts=$(jq -s '[group_by(.status_code)[] | {status: .[0].status_code, count: length}] | sort_by(.count) | reverse' "$probe_file" 2>/dev/null || echo '[]')
    tech_counts=$(jq -s '[.[].technologies[] // empty] | group_by(.) | map({technology: .[0], count: length}) | sort_by(.count) | reverse | .[0:10]' "$probe_file" 2>/dev/null || echo '[]')
    live_hosts=$(jq -s '[.[].host] | unique | length' "$probe_file" 2>/dev/null || echo 0)
    
    jq -n \
        --argjson total "$total_responses" \
        --argjson live "$live_hosts" \
        --argjson by_status "$status_counts" \
        --argjson technologies "$tech_counts" \
        '{
            total_responses: $total,
            live_hosts: $live,
            responses_by_status: $by_status,
            top_technologies: $technologies,
            status: (if $total > 0 then "completed" else "no_results" end)
        }'
}

collect_scan_summary() {
    local target_dir="$1"
    local scan_file="$target_dir/nmap.json"
    
    if [[ ! -f "$scan_file" ]]; then
        echo 'null'
        return
    fi
    
    local total_ports unique_ips top_ports top_services
    total_ports=$(jq 'length' "$scan_file" 2>/dev/null || echo 0)
    
    if [[ "$total_ports" -eq 0 ]]; then
        echo 'null'
        return
    fi
    
    unique_ips=$(jq '[.[].ip] | unique | length' "$scan_file" 2>/dev/null || echo 0)
    top_ports=$(jq '[group_by(.port)[] | {port: .[0].port, count: length}] | sort_by(.count) | reverse | .[0:10]' "$scan_file" 2>/dev/null || echo '[]')
    top_services=$(jq '[group_by(.service)[] | {service: .[0].service, count: length}] | sort_by(.count) | reverse | .[0:10]' "$scan_file" 2>/dev/null || echo '[]')
    
    jq -n \
        --argjson total "$total_ports" \
        --argjson ips "$unique_ips" \
        --argjson ports "$top_ports" \
        --argjson services "$top_services" \
        '{
            total_open_ports: $total,
            unique_ips: $ips,
            top_ports: $ports,
            top_services: $services,
            status: (if $total > 0 then "completed" else "no_results" end)
        }'
}

collect_osint_summary() {
    local target_dir="$1"
    local whois_file="$target_dir/whois.json"
    local ct_file="$target_dir/osint/ct.json"
    local ip_file="$target_dir/osint/ipinfo.jsonl"
    
    local whois_data ct_count ip_count
    whois_data='null'
    ct_count=0
    ip_count=0
    
    if [[ -f "$whois_file" ]]; then
        whois_data=$(cat "$whois_file" 2>/dev/null || echo 'null')
    fi
    
    if [[ -f "$ct_file" ]]; then
        ct_count=$(jq 'length' "$ct_file" 2>/dev/null || echo 0)
    fi
    
    if [[ -f "$ip_file" ]]; then
        ip_count=$(wc -l < "$ip_file" 2>/dev/null || echo 0)
    fi
    
    jq -n \
        --argjson whois "$whois_data" \
        --argjson certificates "$ct_count" \
        --argjson ip_info "$ip_count" \
        '{
            whois_available: ($whois != null),
            certificate_transparency_entries: $certificates,
            ip_information_entries: $ip_info,
            status: (if ($whois != null or $certificates > 0 or $ip_info > 0) then "completed" else "no_results" end)
        }'
}

generate_executive_summary() {
    local target="$1"
    local target_dir="$2"
    
    local findings=()
    local risk_level="low"
    
    local subdomain_count=0
    if [[ -f "$target_dir/subdomains.txt" ]]; then
        subdomain_count=$(wc -l < "$target_dir/subdomains.txt" 2>/dev/null || echo 0)
        if [[ "$subdomain_count" -gt 50 ]]; then
            findings+=("Large attack surface: $subdomain_count subdomains discovered")
            risk_level="medium"
        elif [[ "$subdomain_count" -gt 10 ]]; then
            findings+=("Moderate attack surface: $subdomain_count subdomains")
        fi
    fi
    
    local open_ports=0
    if [[ -f "$target_dir/nmap.json" ]]; then
        open_ports=$(jq 'length' "$target_dir/nmap.json" 2>/dev/null || echo 0)
        if [[ "$open_ports" -gt 20 ]]; then
            findings+=("High number of open ports: $open_ports services exposed")
            risk_level="high"
        elif [[ "$open_ports" -gt 5 ]]; then
            findings+=("Multiple open ports: $open_ports services")
            if [[ "$risk_level" == "low" ]]; then
                risk_level="medium"
            fi
        fi
    fi
    
    local http_services=0
    if [[ -f "$target_dir/probe.jsonl" ]]; then
        http_services=$(wc -l < "$target_dir/probe.jsonl" 2>/dev/null || echo 0)
        if [[ "$http_services" -gt 0 ]]; then
            findings+=("$http_services HTTP/HTTPS services identified")
        fi
    fi
    
    if [[ -f "$target_dir/probe.jsonl" ]]; then
        local admin_panels
        admin_panels=$(grep -i "admin\|login\|dashboard" "$target_dir/probe.jsonl" 2>/dev/null | wc -l || echo 0)
        if [[ "$admin_panels" -gt 0 ]]; then
            findings+=("Potential admin interfaces detected")
            if [[ "$risk_level" == "low" ]]; then
                risk_level="medium"
            fi
        fi
    fi
    
    if [[ ${#findings[@]} -eq 0 ]]; then
        findings+=("Basic reconnaissance completed - limited exposure detected")
    fi
    
    local findings_json
    findings_json=$(printf '%s\n' "${findings[@]}" | json_array)
    
    jq -n \
        --arg target "$target" \
        --arg risk_level "$risk_level" \
        --argjson subdomain_count "$subdomain_count" \
        --argjson open_ports "$open_ports" \
        --argjson http_services "$http_services" \
        --argjson findings "$findings_json" \
        '{
            target: $target,
            risk_assessment: $risk_level,
            key_metrics: {
                subdomains_discovered: $subdomain_count,
                open_ports_found: $open_ports,
                http_services_identified: $http_services
            },
            key_findings: $findings
        }'
}

generate_text_report() {
    local target="$1"
    local target_dir="$2"
    local report_file="$target_dir/report.txt"
    
    log_info "Generating text report..."
    
    cat > "$report_file" << EOF
================================================================================
RECONSH RECONNAISSANCE REPORT
================================================================================

Target: $target
Generated: $(date)
Tool: reconsh v1.0

================================================================================
EXECUTIVE SUMMARY
================================================================================

EOF
    
    if [[ -f "$target_dir/summary.json" ]]; then
        jq -r '.executive_summary.key_findings[]' "$target_dir/summary.json" 2>/dev/null | \
            sed 's/^/- /' >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

================================================================================
SUBDOMAIN ENUMERATION
================================================================================

EOF
    
    if [[ -f "$target_dir/subdomains.txt" ]]; then
        local sub_count
        sub_count=$(wc -l < "$target_dir/subdomains.txt")
        echo "Total subdomains found: $sub_count" >> "$report_file"
        echo "" >> "$report_file"
        head -20 "$target_dir/subdomains.txt" >> "$report_file"
        if [[ "$sub_count" -gt 20 ]]; then
            echo "... (showing first 20 of $sub_count total)" >> "$report_file"
        fi
    else
        echo "No subdomains file found." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

================================================================================
OPEN PORTS
================================================================================

EOF
    
    if [[ -f "$target_dir/nmap.json" ]]; then
        local port_count
        port_count=$(jq 'length' "$target_dir/nmap.json" 2>/dev/null || echo 0)
        echo "Total open ports: $port_count" >> "$report_file"
        echo "" >> "$report_file"
        
        if [[ "$port_count" -gt 0 ]]; then
            jq -r '.[] | "\(.ip):\(.port) (\(.protocol)) - \(.service)"' "$target_dir/nmap.json" 2>/dev/null | \
                head -20 >> "$report_file"
        fi
    else
        echo "No port scan results found." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

================================================================================
HTTP SERVICES
================================================================================

EOF
    
    if [[ -f "$target_dir/probe.jsonl" ]]; then
        local http_count
        http_count=$(wc -l < "$target_dir/probe.jsonl")
        echo "Total HTTP responses: $http_count" >> "$report_file"
        echo "" >> "$report_file"
        
        jq -r 'select(.status_code == 200) | "\(.final_url) - \(.title // "No title")"' "$target_dir/probe.jsonl" 2>/dev/null | \
            head -10 >> "$report_file"
    else
        echo "No HTTP probe results found." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

================================================================================
END OF REPORT
================================================================================
EOF
    
    log_success "Text report generated: $report_file"
}

merge_json_files() {
    local output_file="$1"
    shift
    local input_files=("$@")
    
    local temp_file
    temp_file=$(mktemp)
    
    echo "[]" > "$temp_file"
    
    for file in "${input_files[@]}"; do
        if [[ -f "$file" ]]; then
            jq -s '.[0] + .[1]' "$temp_file" "$file" > "$temp_file.tmp" && \
                mv "$temp_file.tmp" "$temp_file"
        fi
    done
    
    mv "$temp_file" "$output_file"
}

archive_results() {
    local target="$1"
    local target_dir="$2"
    local archive_name="reconsh_${target}_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    log_info "Creating archive: $archive_name"
    
    if command_exists tar; then
        tar -czf "$archive_name" -C "$(dirname "$target_dir")" "$(basename "$target_dir")" 2>/dev/null
        log_success "Archive created: $archive_name"
    else
        log_warn "tar command not available for archiving"
    fi
}
