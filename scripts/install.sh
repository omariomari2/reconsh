#!/bin/bash
#
# install.sh - Installation script for reconsh
#

set -Eeuo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="reconsh"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root. This will install system-wide."
        return 0
    else
        log_info "Not running as root. Will attempt local installation."
        INSTALL_DIR="$HOME/.local/bin"
        return 1
    fi
}

# Create installation directory
create_install_dir() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_info "Creating installation directory: $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
    fi
}

# Install reconsh
install_reconsh() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_dir
    project_dir="$(dirname "$script_dir")"
    
    log_info "Installing reconsh to $INSTALL_DIR"
    
    # Copy main script
    cp "$project_dir/bin/recon.sh" "$INSTALL_DIR/$SCRIPT_NAME"
    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    
    # Create lib directory
    local lib_dir="$INSTALL_DIR/../lib/reconsh"
    mkdir -p "$lib_dir"
    
    # Copy library files
    cp -r "$project_dir/lib/"* "$lib_dir/"
    
    # Update script to use installed lib path
    sed -i.bak "s|LIB_DIR=\"\$(dirname \"\$SCRIPT_DIR\")/lib\"|LIB_DIR=\"$lib_dir\"|" "$INSTALL_DIR/$SCRIPT_NAME"
    rm -f "$INSTALL_DIR/$SCRIPT_NAME.bak"
    
    log_success "reconsh installed successfully"
}

# Check PATH
check_path() {
    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
        log_success "$INSTALL_DIR is in PATH"
    else
        log_warn "$INSTALL_DIR is not in PATH"
        log_info "Add the following to your shell profile:"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

# Main installation function
main() {
    echo "reconsh Installation Script"
    echo "=========================="
    echo
    
    # Check dependencies first
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    if ! "$script_dir/check_deps.sh"; then
        log_error "Dependencies check failed. Please install missing dependencies first."
        exit 1
    fi
    
    echo
    log_info "Starting installation..."
    
    check_root
    create_install_dir
    install_reconsh
    check_path
    
    echo
    log_success "Installation completed!"
    log_info "Run 'reconsh check' to verify the installation"
    log_info "Run 'reconsh --help' for usage information"
}

# Run installation
main "$@"
