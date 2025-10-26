#!/bin/bash
#
# reconsh - Offensive Reconnaissance Toolkit
# A modular Bash toolkit for domain-focused reconnaissance
#
# LEGAL DISCLAIMER:
# This tool is for authorized security testing and educational purposes only.
# Users are responsible for complying with applicable laws and obtaining proper
# authorization before scanning any systems they do not own or have explicit
# permission to test.
#

set -Eeuo pipefail

# Script directory and library path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$(dirname "$SCRIPT_DIR")/lib"

# Source common functions
# shellcheck source=../lib/common.sh
source "$LIB_DIR/common.sh"

# Default configuration
DEFAULT_THREADS=10
DEFAULT_OUTDIR="out"
DEFAULT_TIMEOUT=30

# Global variables
DOMAIN=""
TARGETS_FILE=""
THREADS="$DEFAULT_THREADS"
OUTDIR="$DEFAULT_OUTDIR"
FAST_MODE=false
JSON_OUTPUT=false
NO_CACHE=false
MODULE_TIMEOUT="$DEFAULT_TIMEOUT"
VERBOSE=false

# Usage information
usage() {
    cat << EOF
reconsh - Offensive Reconnaissance Toolkit

USAGE:
    $0 <command> [options]

COMMANDS:
    check       Check dependencies and environment
    subs        Subdomain enumeration
    dns         DNS enumeration and resolution
    probe       HTTP/HTTPS probing
    scan        Port scanning with nmap
    osint       OSINT data collection
    all         Run complete reconnaissance workflow

OPTIONS:
    -d <domain>         Target domain
    -f <file>           File containing target domains (one per line)
    -t <threads>        Number of concurrent threads (default: $DEFAULT_THREADS)
    -o <outdir>         Output directory (default: $DEFAULT_OUTDIR)
    --fast              Fast mode (reduced coverage for speed)
    --json              JSON output format
    --no-cache          Disable caching
    --module-timeout <sec>  Module timeout in seconds (default: $DEFAULT_TIMEOUT)
    -v, --verbose       Verbose output
    -h, --help          Show this help

EXAMPLES:
    $0 check
    $0 all -d example.com -t 20 -o results/
    $0 subs -d example.com --json
    $0 scan -f targets.txt --fast

LEGAL:
    This tool is for authorized security testing only. Users must obtain proper
    authorization before scanning systems they do not own.

EOF
}

# Parse command line arguments
parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    local command="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -f|--file)
                TARGETS_FILE="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -o|--outdir)
                OUTDIR="$2"
                shift 2
                ;;
            --fast)
                FAST_MODE=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --no-cache)
                NO_CACHE=true
                shift
                ;;
            --module-timeout)
                MODULE_TIMEOUT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Validate command
    case "$command" in
        check|subs|dns|probe|scan|osint|all)
            COMMAND="$command"
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac

    # Validate required arguments for most commands
    if [[ "$COMMAND" != "check" ]]; then
        if [[ -z "$DOMAIN" && -z "$TARGETS_FILE" ]]; then
            log_error "Either -d <domain> or -f <file> is required"
            exit 1
        fi
    fi

    # Validate numeric arguments
    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
        log_error "Invalid threads value: $THREADS"
        exit 1
    fi

    if ! [[ "$MODULE_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$MODULE_TIMEOUT" -lt 1 ]]; then
        log_error "Invalid timeout value: $MODULE_TIMEOUT"
        exit 1
    fi
}

# Get target list from domain or file
get_targets() {
    local targets=()
    
    if [[ -n "$DOMAIN" ]]; then
        targets+=("$DOMAIN")
    fi
    
    if [[ -n "$TARGETS_FILE" ]]; then
        if [[ ! -f "$TARGETS_FILE" ]]; then
            log_error "Targets file not found: $TARGETS_FILE"
            exit 1
        fi
        while IFS= read -r line; do
            line=$(echo "$line" | tr -d '\r\n' | xargs)
            if [[ -n "$line" && ! "$line" =~ ^# ]]; then
                targets+=("$line")
            fi
        done < "$TARGETS_FILE"
    fi
    
    if [[ ${#targets[@]} -eq 0 ]]; then
        log_error "No valid targets found"
        exit 1
    fi
    
    printf '%s\n' "${targets[@]}"
}

# Execute command for each target
execute_command() {
    local targets
    readarray -t targets < <(get_targets)
    
    log_info "Starting $COMMAND for ${#targets[@]} target(s) with $THREADS threads"
    
    for target in "${targets[@]}"; do
        log_info "Processing target: $target"
        
        # Create output directory for target
        local target_dir="$OUTDIR/$target"
        mkdir -p "$target_dir"
        
        case "$COMMAND" in
            check)
                check_dependencies
                ;;
            subs)
                run_subdomain_enum "$target" "$target_dir"
                ;;
            dns)
                run_dns_enum "$target" "$target_dir"
                ;;
            probe)
                run_http_probe "$target" "$target_dir"
                ;;
            scan)
                run_port_scan "$target" "$target_dir"
                ;;
            osint)
                run_osint "$target" "$target_dir"
                ;;
            all)
                run_full_recon "$target" "$target_dir"
                ;;
        esac
    done
}

# Run full reconnaissance workflow
run_full_recon() {
    local target="$1"
    local target_dir="$2"
    
    log_info "Running full reconnaissance for $target"
    
    # Run modules in sequence with caching
    run_subdomain_enum "$target" "$target_dir"
    run_dns_enum "$target" "$target_dir"
    run_http_probe "$target" "$target_dir"
    run_port_scan "$target" "$target_dir"
    run_osint "$target" "$target_dir"
    
    # Generate summary
    generate_summary "$target" "$target_dir"
}

# Placeholder functions for modules (will be implemented in separate files)
check_dependencies() {
    source "$LIB_DIR/common.sh"
    check_deps
}

run_subdomain_enum() {
    local target="$1"
    local target_dir="$2"
    source "$LIB_DIR/subs.sh"
    enumerate_subdomains "$target" "$target_dir"
}

run_dns_enum() {
    local target="$1"
    local target_dir="$2"
    source "$LIB_DIR/dns.sh"
    enumerate_dns "$target" "$target_dir"
}

run_http_probe() {
    local target="$1"
    local target_dir="$2"
    source "$LIB_DIR/probe.sh"
    probe_http "$target" "$target_dir"
}

run_port_scan() {
    local target="$1"
    local target_dir="$2"
    source "$LIB_DIR/scan.sh"
    scan_ports "$target" "$target_dir"
}

run_osint() {
    local target="$1"
    local target_dir="$2"
    source "$LIB_DIR/osint.sh"
    collect_osint "$target" "$target_dir"
}

generate_summary() {
    local target="$1"
    local target_dir="$2"
    source "$LIB_DIR/output.sh"
    create_summary "$target" "$target_dir"
}

# Main execution
main() {
    # Show banner
    log_info "reconsh - Offensive Reconnaissance Toolkit"
    log_info "Use responsibly and only on authorized targets"
    echo
    
    parse_args "$@"
    execute_command
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
