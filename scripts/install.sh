#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# envseal-cli installer
# Downloads and installs the envseal binary, or installs from a local file.
# =============================================================================

# Configuration defaults
readonly REPO="viswajith275/envseal-cli"
readonly BIN_NAME="envseal"
readonly DEFAULT_INSTALL_DIR="$HOME/.local/bin"
readonly VERSION_DEFAULT="latest"

# Script variables
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
VERSION="$VERSION_DEFAULT"
LOCAL_FILE=""
DRY_RUN=false

# Colors for output (only if terminal)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly NC='\033[0m' # No Color
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly NC=''
fi

# Logging functions
log_info() {
    echo -e "${GREEN}✓${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $*" >&2
}

log_error() {
    echo -e "${RED}✗${NC} $*" >&2
}

usage() {
    cat <<EOF
Usage: install.sh [options]

Downloads and installs $BIN_NAME, or installs it from a local file.
Updates the current shell's configuration file if it exists.

Options:
  -d, --dir <path>      Install directory (default: $DEFAULT_INSTALL_DIR)
  -v, --version <tag>   Install a specific release tag (default: latest)
                         Example: v1.2.3
  -f, --file <path>     Manual install from local .tar.gz or binary
  --dry-run              Show what would be done without making changes
  -h, --help             Show this help message and exit

Examples:
  # Normal install (auto-detects OS/arch, downloads latest)
  ./install.sh

  # Install a specific version
  ./install.sh --version v1.2.3

  # Install to a custom directory
  ./install.sh --dir /usr/local/bin

  # Manual install from a downloaded tarball
  ./install.sh --file ~/Downloads/$BIN_NAME-macos-aarch64.tar.gz

  # Manual install from a built binary
  ./install.sh --file ./target/release/$BIN_NAME

  # Dry run to see what would be done
  ./install.sh --dry-run
EOF
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -f|--file)
                LOCAL_FILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
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
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Fetch URL using curl or wget
fetch() {
    local url="$1"
    
    if command_exists curl; then
        curl -fsSL "$url"
    elif command_exists wget; then
        wget -qO- "$url"
    else
        log_error "Neither curl nor wget is installed"
        exit 1
    fi
}

# Detect current shell and return its name (bash, zsh, fish, etc.)
detect_current_shell() {
    local shell_path="${SHELL:-/bin/bash}"
    basename "$shell_path"
}

# Get the config file path for the detected shell
get_shell_config_path() {
    local shell="$1"
    
    case "$shell" in
        bash)
            echo "$HOME/.bashrc"
            ;;
        zsh)
            echo "$HOME/.zshrc"
            ;;
        fish)
            echo "$HOME/.config/fish/config.fish"
            ;;
        ksh|mksh)
            echo "$HOME/.kshrc"
            ;;
        tcsh)
            echo "$HOME/.tcshrc"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Validate install directory
validate_install_dir() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            log_error "Cannot create install directory: $INSTALL_DIR"
            exit 1
        fi
        log_info "Created install directory: $INSTALL_DIR"
    fi
    
    if [[ ! -w "$INSTALL_DIR" ]]; then
        log_error "Install directory is not writable: $INSTALL_DIR"
        exit 1
    fi
}

# Install from local file (tarball or binary)
install_from_local() {
    if [[ ! -e "$LOCAL_FILE" ]]; then
        log_error "File not found: $LOCAL_FILE"
        exit 1
    fi

    local target_path="$INSTALL_DIR/$BIN_NAME"
    
    case "$LOCAL_FILE" in
        *.tar.gz|*.tgz)
            log_info "Installing from archive: $LOCAL_FILE"
            local tmp_dir
            tmp_dir=$(mktemp -d) || exit 1
            trap "rm -rf '$tmp_dir'" EXIT

            if ! tar -xzf "$LOCAL_FILE" -C "$tmp_dir" 2>/dev/null; then
                log_error "Failed to extract archive: $LOCAL_FILE"
                exit 1
            fi

            local found_bin
            found_bin=$(find "$tmp_dir" -maxdepth 2 -type f -name "$BIN_NAME*" ! -name "*.txt" ! -name "*.md" 2>/dev/null | head -n 1)
            
            if [[ -z "$found_bin" ]]; then
                log_error "No '$BIN_NAME' binary found in archive"
                exit 1
            fi

            if [[ "$DRY_RUN" == false ]]; then
                cp "$found_bin" "$target_path"
                chmod +x "$target_path"
            fi
            ;;
        *)
            log_info "Installing from binary: $LOCAL_FILE"
            if [[ "$DRY_RUN" == false ]]; then
                cp "$LOCAL_FILE" "$target_path"
                chmod +x "$target_path"
            fi
            ;;
    esac

    log_info "Binary installed to: $target_path"
}

# Detect OS and architecture
detect_platform() {
    local os arch target
    
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64)
                    target="linux-musl-x86_64"
                    ;;
                aarch64|arm64)
                    target="linux-musl-aarch64"
                    ;;
                *)
                    target=""
                    ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64)
                    target="macos-x86_64"
                    ;;
                arm64)
                    target="macos-aarch64"
                    ;;
                *)
                    target=""
                    ;;
            esac
            ;;
        *)
            target=""
            ;;
    esac

    if [[ -z "$target" ]]; then
        log_error "Unsupported platform: $os/$arch"
        log_error "Install manually with: ./install.sh --file <path-to-binary-or-tarball>"
        exit 1
    fi

    echo "$target"
}

# Download and install from GitHub releases
install_from_release() {
    local target release_url tmp_dir
    
    target=$(detect_platform)
    log_info "Detected platform: $target"

    # Construct GitHub API URL
    local api_url
    if [[ "$VERSION" == "latest" ]]; then
        api_url="https://api.github.com/repos/$REPO/releases/latest"
    else
        api_url="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
    fi

    log_info "Fetching release information..."
    
    release_url=$(fetch "$api_url" 2>/dev/null | grep -o "https://github.com/[^\"]*$target\.tar\.gz" | head -n 1 || true)

    if [[ -z "$release_url" ]]; then
        log_error "Could not find release for $target (version: $VERSION)"
        log_error "Install manually with: ./install.sh --file <path-to-binary-or-tarball>"
        exit 1
    fi

    log_info "Downloading from: $release_url"
    
    local tmp_dir target_path
    tmp_dir=$(mktemp -d) || exit 1
    trap "rm -rf '$tmp_dir'" EXIT

    if ! fetch "$release_url" 2>/dev/null | tar -xz -C "$tmp_dir"; then
        log_error "Failed to download or extract release"
        exit 1
    fi

    # Find the binary in the extracted archive
    local found_bin
    found_bin=$(find "$tmp_dir" -maxdepth 2 -type f -name "$BIN_NAME*" ! -name "*.txt" ! -name "*.md" 2>/dev/null | head -n 1)
    
    if [[ -z "$found_bin" ]]; then
        log_error "No '$BIN_NAME' binary found in release"
        exit 1
    fi

    target_path="$INSTALL_DIR/$BIN_NAME"
    if [[ "$DRY_RUN" == false ]]; then
        cp "$found_bin" "$target_path"
        chmod +x "$target_path"
    fi

    log_info "Binary installed to: $target_path"
}

# Update shell configuration
update_shell_config() {
    local shell config_file
    
    shell=$(detect_current_shell)
    config_file=$(get_shell_config_path "$shell")

    if [[ -z "$config_file" ]]; then
        log_warn "Unsupported shell: $shell (no automatic config update)"
        return 0
    fi

    # Only proceed if config file exists
    if [[ ! -f "$config_file" ]]; then
        log_warn "Shell config file not found: $config_file (skipping config update)"
        return 0
    fi

    log_info "Detected shell: $shell"
    update_config_for_shell "$shell" "$config_file"
}

# Update configuration for a specific shell
update_config_for_shell() {
    local shell="$1"
    local config_file="$2"
    local modified=false

    case "$shell" in
        fish)
            modified=$(update_fish_config "$config_file")
            ;;
        *)
            modified=$(update_posix_config "$config_file")
            ;;
    esac

    if [[ "$modified" == "true" ]]; then
        log_info "Updated shell configuration: $config_file"
    else
        log_info "Shell configuration already up-to-date: $config_file"
    fi
}

# Update POSIX-compatible shell config (bash, zsh, ksh, etc.)
update_posix_config() {
    local config_file="$1"
    local modified=false

    # Add PATH if not already present
    if ! grep -q "$(printf '%s\n' "$INSTALL_DIR" | sed 's/[[\.*^$/]/\\&/g')" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "# Added by $BIN_NAME installer"
                echo "export PATH=\"$INSTALL_DIR:\$PATH\""
            } >> "$config_file"
        fi
        modified=true
    fi

    # Add shell function if not already present
    local marker="# >>> $BIN_NAME shell integration >>>"
    if ! grep -qF "$marker" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "$marker"
                echo "$BIN_NAME() {"
                echo "    if [ \"\$1\" = \"load\" ]; then"
                echo "        eval \"\$(command $BIN_NAME \"\$@\")\""
                echo "    else"
                echo "        command $BIN_NAME \"\$@\""
                echo "    fi"
                echo "}"
                echo "# <<< $BIN_NAME shell integration <<<"
            } >> "$config_file"
        fi
        modified=true
    fi

    echo "$modified"
}

# Update fish shell config
update_fish_config() {
    local config_file="$1"
    local modified=false

    # Add PATH if not already present
    if ! grep -q "$(printf '%s\n' "$INSTALL_DIR" | sed 's/[[\.*^$/]/\\&/g')" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "# Added by $BIN_NAME installer"
                echo "fish_add_path $INSTALL_DIR"
            } >> "$config_file"
        fi
        modified=true
    fi

    # Add function if not already present
    local marker="# >>> $BIN_NAME shell integration >>>"
    if ! grep -qF "$marker" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "$marker"
                echo "function $BIN_NAME"
                echo "    if [ \"\$argv[1]\" = \"load\" ]"
                echo "        eval (command $BIN_NAME \$argv)"
                echo "    else"
                echo "        command $BIN_NAME \$argv"
                echo "    end"
                echo "end"
                echo "# <<< $BIN_NAME shell integration <<<"
            } >> "$config_file"
        fi
        modified=true
    fi

    echo "$modified"
}

# Verify installation
verify_installation() {
    local binary_path="$INSTALL_DIR/$BIN_NAME"
    
    # Check if binary exists
    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found: $binary_path"
        return 1
    fi

    # Check if binary is executable
    if [[ ! -x "$binary_path" ]]; then
        log_error "Binary is not executable: $binary_path"
        return 1
    fi

    # Try to execute the binary with common version flags
    local version_output=""
    if "$binary_path" --version >/dev/null 2>&1; then
        version_output=$("$binary_path" --version 2>&1)
    elif "$binary_path" -V >/dev/null 2>&1; then
        version_output=$("$binary_path" -V 2>&1)
    elif "$binary_path" version >/dev/null 2>&1; then
        version_output=$("$binary_path" version 2>&1)
    elif "$binary_path" --help >/dev/null 2>&1; then
        # If no version flag works, at least try --help
        version_output=$("$binary_path" --help 2>&1 | head -n 1)
    else
        # If all else fails, just verify it's in the system
        if file "$binary_path" | grep -q "ELF\|Mach-O\|executable"; then
            log_warn "Binary exists but couldn't verify execution (missing version/help flags)"
            log_info "Binary installed: $binary_path"
            return 0
        else
            log_error "Binary exists but is not a valid executable"
            return 1
        fi
    fi

    if [[ -n "$version_output" ]]; then
        log_info "Binary verified: $binary_path"
        log_info "Version info: $(echo "$version_output" | head -n 1)"
    fi
    
    return 0
}

# Main installation flow
main() {
    parse_args "$@"

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "DRY RUN MODE - no changes will be made"
    fi

    echo ""
    log_info "Installing $BIN_NAME..."

    validate_install_dir

    if [[ -n "$LOCAL_FILE" ]]; then
        install_from_local
    else
        install_from_release
    fi

    update_shell_config

    if [[ "$DRY_RUN" == false ]]; then
        echo ""
        
        # Verify installation (non-fatal if it fails)
        if verify_installation; then
            log_info "Installation successful!"
        else
            log_warn "Could not fully verify installation"
        fi
        
        echo ""
        echo "Next steps:"
        echo "  1. Reload your shell configuration:"
        echo "     source $(get_shell_config_path "$(detect_current_shell)")"
        echo ""
        echo "  2. Test the installation:"
        echo "     $BIN_NAME --version"
        echo ""
        echo "  3. Load environment variables:"
        echo "     $BIN_NAME load <KEYS>..."
    else
        echo ""
        log_info "Dry run complete - no changes were made"
    fi
}

# Run main function
main "$@"