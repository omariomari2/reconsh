#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_debug() {
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $*" >&2
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_deps() {
    local missing_deps=()
    local required_deps=("bash" "curl" "jq" "nmap" "dig" "whois" "awk" "sed" "xargs" "sort" "uniq")
    
    log_info "Checking dependencies..."
    
    for dep in "${required_deps[@]}"; do
        if ! command_exists "$dep"; then
            missing_deps+=("$dep")
        else
            log_debug "Found: $dep"
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies:"
        printf '  - %s\n' "${missing_deps[@]}"
        log_error "Please install missing dependencies and try again"
        return 1
    fi
    
    log_success "All dependencies found"
    
    local optional_deps=("sudo")
    for dep in "${optional_deps[@]}"; do
        if command_exists "$dep"; then
            log_debug "Optional dependency found: $dep"
        else
            log_warn "Optional dependency missing: $dep"
        fi
    done
    
    return 0
}

create_cache_dir() {
    local target_dir="$1"
    local cache_dir="$target_dir/.cache"
    mkdir -p "$cache_dir"
    echo "$cache_dir"
}

cache_key() {
    local url="$1"
    local date_key
    date_key=$(date +%Y%m%d)
    echo "${url//[^a-zA-Z0-9]/_}_${date_key}"
}

cache_exists() {
    local cache_file="$1"
    [[ -f "$cache_file" ]] && [[ -s "$cache_file" ]]
}

cached_curl() {
    local url="$1"
    local cache_dir="$2"
    local cache_file="$cache_dir/$(cache_key "$url")"
    local max_retries=3
    local retry_delay=2
    
    if [[ "${NO_CACHE:-false}" != "true" ]] && cache_exists "$cache_file"; then
        log_debug "Using cached result for: $url"
        cat "$cache_file"
        return 0
    fi
    
    log_debug "Fetching: $url"
    
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if curl -s -L --max-time "${MODULE_TIMEOUT:-30}" \
               --user-agent "reconsh/1.0 (Security Research)" \
               "$url" > "$cache_file.tmp" 2>/dev/null; then
            mv "$cache_file.tmp" "$cache_file"
            cat "$cache_file"
            return 0
        else
            log_debug "Attempt $attempt failed for: $url"
            rm -f "$cache_file.tmp"
            if [[ $attempt -lt $max_retries ]]; then
                sleep $((retry_delay * attempt))
            fi
            ((attempt++))
        fi
    done
    
    log_error "Failed to fetch after $max_retries attempts: $url"
    return 1
}

rate_limit() {
    local min_delay=${1:-1}
    local max_delay=${2:-3}
    local delay=$((RANDOM % (max_delay - min_delay + 1) + min_delay))
    sleep "$delay"
}

is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

get_root_domain() {
    local domain="$1"
    echo "$domain" | awk -F. '{print $(NF-1)"."$NF}'
}

is_subdomain_of() {
    local subdomain="$1"
    local root_domain="$2"
    [[ "$subdomain" == *".$root_domain" ]] || [[ "$subdomain" == "$root_domain" ]]
}

clean_list() {
    sort -u | grep -v '^$' | tr -d '\r'
}

json_object() {
    local -A pairs
    while [[ $# -gt 0 ]]; do
        local key="$1"
        local value="$2"
        pairs["$key"]="$value"
        shift 2
    done
    
    local json_args=()
    for key in "${!pairs[@]}"; do
        json_args+=(--arg "$key" "${pairs[$key]}")
    done
    
    jq -n "${json_args[@]}" '{($ARGS.named | to_entries[] | .key): .value}'
}

json_array() {
    jq -R . | jq -s .
}

timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

show_progress() {
    local current="$1"
    local total="$2"
    local item="${3:-items}"
    local percent=$((current * 100 / total))
    printf "\r${CYAN}[%3d%%]${NC} Processing %s (%d/%d)" "$percent" "$item" "$current" "$total" >&2
}

clear_progress() {
    printf "\r%50s\r" "" >&2
}

parallel_exec() {
    local threads="$1"
    shift
    xargs -P "$threads" -I {} bash -c "$*" -- {}
}

is_file_too_large() {
    local file="$1"
    local max_size_mb="${2:-10}"
    local max_size_bytes=$((max_size_mb * 1024 * 1024))
    
    if [[ -f "$file" ]]; then
        local file_size
        file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
        [[ "$file_size" -gt "$max_size_bytes" ]]
    else
        return 1
    fi
}

export -f log_info log_success log_warn log_error log_debug
export -f command_exists cached_curl rate_limit
export -f is_valid_domain get_root_domain is_subdomain_of
export -f clean_list json_object json_array timestamp
export -f show_progress clear_progress parallel_exec
