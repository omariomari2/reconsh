#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_DOMAIN="example.com"
TEST_OUTPUT_DIR="test_output"
RECON_SCRIPT="$PROJECT_DIR/bin/recon.sh"

TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${YELLOW}[TEST]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++))
}

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    log_info "Running test: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        log_success "$test_name"
    else
        log_error "$test_name"
    fi
}

cleanup() {
    if [[ -d "$TEST_OUTPUT_DIR" ]]; then
        rm -rf "$TEST_OUTPUT_DIR"
        log_info "Cleaned up test output directory"
    fi
}

main() {
    echo "reconsh Basic Functionality Test"
    echo "================================"
    echo
    
    cd "$PROJECT_DIR"
    
    cleanup
    
    run_test "Main script exists and is executable" \
        "[[ -x '$RECON_SCRIPT' ]]"
    
    run_test "Dependencies check command" \
        "'$RECON_SCRIPT' check"
    
    run_test "Help command displays usage" \
        "'$RECON_SCRIPT' --help | grep -q 'USAGE'"
    
    run_test "Invalid command handling" \
        "! '$RECON_SCRIPT' invalid_command 2>/dev/null"
    
    run_test "Missing domain argument handling" \
        "! '$RECON_SCRIPT' subs 2>/dev/null"
    
    run_test "Output directory creation" \
        "'$RECON_SCRIPT' subs -d '$TEST_DOMAIN' -o '$TEST_OUTPUT_DIR' --module-timeout 5 && [[ -d '$TEST_OUTPUT_DIR/$TEST_DOMAIN' ]]"
    
    if [[ -d "$TEST_OUTPUT_DIR/$TEST_DOMAIN" ]]; then
        run_test "Subdomain enumeration creates output file" \
            "[[ -f '$TEST_OUTPUT_DIR/$TEST_DOMAIN/subdomains.txt' ]]"
    else
        log_error "Subdomain enumeration creates output file (directory not found)"
    fi
    
    run_test "JSON output format option" \
        "'$RECON_SCRIPT' subs -d '$TEST_DOMAIN' -o '$TEST_OUTPUT_DIR' --json --module-timeout 5"
    
    run_test "Fast mode option" \
        "'$RECON_SCRIPT' subs -d '$TEST_DOMAIN' -o '$TEST_OUTPUT_DIR' --fast --module-timeout 5"
    
    run_test "Verbose mode option" \
        "'$RECON_SCRIPT' subs -d '$TEST_DOMAIN' -o '$TEST_OUTPUT_DIR' -v --module-timeout 5"
    
    local lib_files=("common.sh" "subs.sh" "dns.sh" "probe.sh" "scan.sh" "osint.sh" "output.sh")
    for lib_file in "${lib_files[@]}"; do
        run_test "Library file exists: $lib_file" \
            "[[ -f 'lib/$lib_file' ]]"
    done
    
    local config_files=(".shellcheckrc" ".gitignore" "README.md" "LICENSE")
    for config_file in "${config_files[@]}"; do
        run_test "Configuration file exists: $config_file" \
            "[[ -f '$config_file' ]]"
    done
    
    cleanup
    
    echo
    echo "Test Summary"
    echo "============"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo "Total tests:  $((TESTS_PASSED + TESTS_FAILED))"
    echo
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "All tests passed!"
        exit 0
    else
        log_error "$TESTS_FAILED test(s) failed"
        exit 1
    fi
}

trap cleanup EXIT

main "$@"
