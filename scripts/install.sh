#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# envseal-cli Installer (Linux & macOS)
# =============================================================================

readonly REPO="viswajith275/envseal-cli"
readonly BIN_NAME="envseal"
readonly DEFAULT_INSTALL_DIR="$HOME/.local/bin"
readonly VERSION_DEFAULT="latest"
readonly ARCHIVE_EXT=".tar.gz"

# State
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
VERSION="$VERSION_DEFAULT"
LOCAL_FILE=""
DRY_RUN=false
SKIP_VERIFY=false

# Platform vars
PLATFORM=""
TMP_DIR=""

# UI & Colors
if [[ -t 1 ]]; then
    readonly C_RED='\033[0;31m'
    readonly C_GRN='\033[0;32m'
    readonly C_BLU='\033[0;34m'
    readonly C_YEL='\033[1;33m'
    readonly C_CYA='\033[0;36m'
    readonly C_BOLD='\033[1m'
    readonly C_RESET='\033[0m'
else
    readonly C_RED='' C_GRN='' C_BLU='' C_YEL='' C_CYA='' C_BOLD='' C_RESET=''
fi

log_info()    { echo -e "${C_BLU}==>${C_RESET} $*" >&2; }
log_success() { echo -e "${C_GRN}✔${C_RESET} $*" >&2; }
log_warn()    { echo -e "${C_YEL}⚠${C_RESET} $*" >&2; }
log_error()   { echo -e "${C_RED}✖${C_RESET} $*" >&2; }

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<EOF
${C_BOLD}Usage:${C_RESET} install.sh [options]

Installs the ${BIN_NAME} binary from GitHub Releases or a local archive.

${C_BOLD}Options:${C_RESET}
  -d, --dir <path>      Target install directory (default: $DEFAULT_INSTALL_DIR)
  -v, --version <tag>   Release version to install (default: latest)
  -f, --file <path>     Install directly from a local archive or binary
  --no-verify           Skip SHA-256 checksum verification
  --dry-run             Preview actions without making changes
  -h, --help            Show this help message

${C_BOLD}Examples:${C_RESET}
  ./install.sh
  ./install.sh --version v1.2.0
  ./install.sh --dir /usr/local/bin
  ./install.sh --file ./envseal-linux-aarch64.tar.gz
EOF
}

# --- Argument Parsing ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)      INSTALL_DIR="$2"; shift 2 ;;
            -v|--version)  VERSION="$2"; shift 2 ;;
            -f|--file)     LOCAL_FILE="$2"; shift 2 ;;
            --no-verify)   SKIP_VERIFY=true; shift ;;
            --dry-run)     DRY_RUN=true; shift ;;
            -h|--help)     usage; exit 0 ;;
            *)             log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    if [[ "$VERSION" != "latest" && "$VERSION" != v* ]]; then
        VERSION="v$VERSION"
    fi
}

# --- HTTP Helpers ---
has_cmd() { command -v "$1" >/dev/null 2>&1; }

http_get() {
    local url="$1"
    if has_cmd curl; then
        curl -sSL "$url"
    elif has_cmd wget; then
        wget -qO- "$url" 2>/dev/null || true
    else
        log_error "curl or wget is required to run this installer."
        exit 1
    fi
}

get_remote_size() {
    local url="$1"
    if has_cmd curl; then
        curl -sIL "$url" | tr -d '\r' | awk '/^[Cc]ontent-[Ll]ength:/ {len=$2} END {print len}'
    elif has_cmd wget; then
        wget --spider --server-response "$url" 2>&1 | tr -d '\r' | awk '/^[Cc]ontent-[Ll]ength:/ {len=$2} END {print len}'
    fi
}

http_download_with_progress() {
    local url="$1" dest="$2"
    local total_bytes
    total_bytes="$(get_remote_size "$url" || echo 0)"

    if has_cmd curl; then
        curl -fsSL -o "$dest" "$url" &
    elif has_cmd wget; then
        wget -q -O "$dest" "$url" &
    else
        log_error "curl or wget is required to run this installer."
        exit 1
    fi
    local dl_pid=$!

    while kill -0 "$dl_pid" 2>/dev/null; do
        local cur_bytes=0
        if [[ -f "$dest" ]]; then
            cur_bytes=$(wc -c < "$dest" | tr -d '[:space:]')
        fi

        if [[ -n "$total_bytes" && "$total_bytes" -gt 0 ]]; then
            local pct=$(( cur_bytes * 100 / total_bytes ))
            local cur_mb total_mb
            cur_mb=$(awk -v b="$cur_bytes" 'BEGIN { printf "%.2f", b/1048576 }')
            total_mb=$(awk -v b="$total_bytes" 'BEGIN { printf "%.2f", b/1048576 }')
            printf "\r\033[K%b==>%b Downloading: %s MB / %s MB (%d%%)" "${C_BLU}" "${C_RESET}" "$cur_mb" "$total_mb" "$pct" >&2
        else
            local cur_mb
            cur_mb=$(awk -v b="$cur_bytes" 'BEGIN { printf "%.2f", b/1048576 }')
            printf "\r\033[K%b==>%b Downloading: %s MB" "${C_BLU}" "${C_RESET}" "$cur_mb" >&2
        fi
        sleep 0.1
    done

    wait "$dl_pid" || {
        printf "\r\033[K" >&2
        log_error "Download failed."
        exit 1
    }

    local final_bytes
    final_bytes=$(wc -c < "$dest" | tr -d '[:space:]')
    local final_mb
    final_mb=$(awk -v b="$final_bytes" 'BEGIN { printf "%.2f", b/1048576 }')
    printf "\r\033[K%b✔%b Download complete (%s MB)\n" "${C_GRN}" "${C_RESET}" "$final_mb" >&2
}

# --- Platform Detection ---
detect_platform() {
    local os arch libc
    os="$(uname -s)"
    arch="$(uname -m)"

    # Detect libc on Linux (musl vs glibc)
    is_musl() {
        # Most reliable checks first
        if [[ -f /lib/ld-musl-x86_64.so.1 || -f /lib/ld-musl-aarch64.so.1 ]]; then
            return 0
        fi
        if command -v ldd >/dev/null 2>&1; then
            if ldd --version 2>&1 | grep -qi musl; then
                return 0
            fi
        fi
        # Alpine / busybox fallback
        if [[ -f /etc/alpine-release ]]; then
            return 0
        fi
        return 1
    }

    case "$os" in
        Linux)
            if is_musl; then
                libc="musl"
            else
                libc="gnu"
            fi

            case "$arch" in
                x86_64|amd64)
                    if [[ "$libc" == "musl" ]]; then
                        PLATFORM="linux-musl-x86_64"
                    else
                        PLATFORM="linux-musl-x86_64"
                        log_info "No glibc x86_64 binary published; using static musl binary (works on glibc too)"
                    fi
                    ;;
                aarch64|arm64)
                    if [[ "$libc" == "musl" ]]; then
                        log_error "No musl (Alpine) aarch64 binary is published yet."
                        log_error "Available Linux assets: linux-musl-x86_64, linux-aarch64 (glibc only)"
                        exit 1
                    else
                        PLATFORM="linux-aarch64"
                    fi
                    ;;
                *)
                    PLATFORM=""
                    ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                arm64) PLATFORM="macos-aarch64" ;;
                x86_64)
                    log_error "Intel Macs (x86_64) are not supported by prebuilt releases."
                    exit 1
                    ;;
                *) PLATFORM="" ;;
            esac
            ;;
        *)
            PLATFORM=""
            ;;
    esac

    if [[ -z "$PLATFORM" ]]; then
        log_error "Unsupported operating system/architecture: $os/$arch"
        log_error "Supported: Linux (x86_64 musl/glibc, aarch64 glibc) and macOS (Apple Silicon)"
        exit 1
    fi

    log_info "Detected platform: $PLATFORM"
}

# --- Checksum Verification ---
verify_checksum() {
    local target_file="$1" sidecar_url="$2"
    [[ "$SKIP_VERIFY" == true ]] && return 0

    log_info "Verifying SHA-256 checksum..."
    local sidecar_content
    sidecar_content="$(http_get "$sidecar_url")"
    [[ -z "$sidecar_content" ]] && { log_warn "Checksum file unavailable. Skipping verification."; return 0; }

    local expected actual
    expected="$(echo "$sidecar_content" | awk '{print $1; exit}')"
    [[ -z "$expected" ]] && return 0

    if has_cmd sha256sum; then
        actual="$(sha256sum "$target_file" | awk '{print $1}')"
    elif has_cmd shasum; then
        actual="$(shasum -a 256 "$target_file" | awk '{print $1}')"
    else
        log_warn "No sha256sum/shasum utility found. Skipping checksum verification."
        return 0
    fi

    if [[ "$expected" != "$actual" ]]; then
        log_error "Checksum mismatch! Expected $expected but calculated $actual."
        exit 1
    fi

    log_success "Checksum verified"
}

# --- Extraction ---
extract_archive() {
    local src="$1" dest="$2"
    case "$src" in
        *.tar.gz|*.tgz)
            tar -xzf "$src" -C "$dest" ;;
        *)
            cp "$src" "$dest/$BIN_NAME"
            chmod +x "$dest/$BIN_NAME"
            ;;
    esac
}

# --- Installation ---
install_binary() {
    local target="$INSTALL_DIR/$BIN_NAME"

    if [[ ! -d "$INSTALL_DIR" ]]; then
        if [[ "$DRY_RUN" == false ]]; then
            mkdir -p "$INSTALL_DIR" || { log_error "Failed to create $INSTALL_DIR"; exit 1; }
        fi
        log_info "Target directory: $INSTALL_DIR"
    fi

    local source_archive=""
    if [[ -n "$LOCAL_FILE" ]]; then
        [[ ! -f "$LOCAL_FILE" ]] && { log_error "Local file not found: $LOCAL_FILE"; exit 1; }
        source_archive="$LOCAL_FILE"
        log_info "Installing from local file: $source_archive"
    else
        local api_url="https://api.github.com/repos/$REPO/releases/${VERSION/latest/latest}"
        [[ "$VERSION" != "latest" ]] && api_url="https://api.github.com/repos/$REPO/releases/tags/$VERSION"

        log_info "Fetching release info for $VERSION ($PLATFORM)..."
        local api_res
        api_res="$(http_get "$api_url")"

        if echo "$api_res" | grep -qi "API rate limit exceeded"; then
            log_error "GitHub API rate limit exceeded. Provide a file directly via --file."
            exit 1
        fi

        local dl_url
        dl_url="$(echo "$api_res" | grep -o "https://github.com/[^\"]*${PLATFORM}${ARCHIVE_EXT//./\\.}" | head -n 1 || true)"
        if [[ -z "$dl_url" ]]; then
            log_error "Could not find a downloadable release asset for $PLATFORM ($VERSION)."
            exit 1
        fi

        source_archive="$TMP_DIR/download${ARCHIVE_EXT}"
        http_download_with_progress "$dl_url" "$source_archive"
        verify_checksum "$source_archive" "${dl_url}.sha256"
    fi

    local extract_dir="$TMP_DIR/extracted"
    mkdir -p "$extract_dir"
    extract_archive "$source_archive" "$extract_dir"

    local binary_src
    binary_src="$(find "$extract_dir" -type f -name "$BIN_NAME" | head -n 1 || true)"

    if [[ -z "$binary_src" ]]; then
        binary_src="$(find "$extract_dir" -maxdepth 2 -type f -perm -111 ! -name "*.*" | head -n 1 || true)"
    fi

    if [[ -z "$binary_src" || ! -f "$binary_src" ]]; then
        log_error "Could not locate $BIN_NAME executable in archive."
        exit 1
    fi

    if [[ "$DRY_RUN" == false ]]; then
        cp "$binary_src" "$target"
        chmod +x "$target"
    fi
    log_success "Installed $BIN_NAME to ${C_BOLD}$target${C_RESET}"
}

# --- Shell Detection & PATH Configuration ---
detect_shell() {
    local shell_bin=""
    if has_cmd ps; then
        shell_bin="$(ps -p "$PPID" -o comm= 2>/dev/null | tr -d '[:space:]-')"
        shell_bin="$(basename "$shell_bin" 2>/dev/null || true)"
    fi
    if [[ -z "$shell_bin" ]]; then
        shell_bin="$(basename "${SHELL:-bash}")"
    fi
    echo "$shell_bin"
}

get_shell_config_file() {
    local current_shell="$1"
    case "$current_shell" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash) echo "$HOME/.bashrc" ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        *)    echo "" ;;
    esac
}

update_path_in_config() {
    local current_shell config_file
    current_shell="$(detect_shell)"
    config_file="$(get_shell_config_file "$current_shell")"

    if [[ -z "$config_file" ]]; then
        log_warn "Shell '$current_shell' configuration file not recognized. Please add '$INSTALL_DIR' to PATH manually."
        return 0
    fi

    if [[ ! -f "$config_file" ]]; then
        mkdir -p "$(dirname "$config_file")" 2>/dev/null || true
        touch "$config_file" 2>/dev/null || { log_warn "Could not create $config_file"; return 0; }
    fi

    if grep -qF "$INSTALL_DIR" "$config_file" 2>/dev/null; then
        log_info "PATH configuration already present in $config_file"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[Dry-run] Would append PATH configuration to $config_file"
        return 0
    fi

    if [[ "$current_shell" == "fish" ]]; then
        echo -e "\n# Added by $BIN_NAME installer\nfish_add_path \"$INSTALL_DIR\"" >> "$config_file"
    else
        echo -e "\n# Added by $BIN_NAME installer\nexport PATH=\"$INSTALL_DIR:\$PATH\"" >> "$config_file"
    fi

    log_success "Added ${C_BOLD}$INSTALL_DIR${C_RESET} to PATH in ${C_BOLD}$config_file${C_RESET}"
}

# --- Main Entrypoint ---
main() {
    parse_args "$@"
    TMP_DIR="$(mktemp -d)"

    echo -e "${C_BOLD}Installing ${BIN_NAME}...${C_RESET}"
    [[ "$DRY_RUN" == true ]] && log_warn "Running in DRY-RUN mode. No files will be modified."

    detect_platform
    install_binary
    update_path_in_config

    echo ""
    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry run complete. No modifications made."
        return 0
    fi

    local current_shell config_file
    current_shell="$(detect_shell)"
    config_file="$(get_shell_config_file "$current_shell")"

    log_success "${C_BOLD}Installation successful!${C_RESET}"
    echo ""
    echo -e "${C_BOLD}1. Apply PATH changes:${C_RESET}"
    if [[ -n "$config_file" ]]; then
        echo -e "   Run: ${C_CYA}source $config_file${C_RESET} (or restart your terminal)"
    else
        echo -e "   Add ${C_CYA}export PATH=\"$INSTALL_DIR:\$PATH\"${C_RESET} to your shell configuration."
    fi

    echo ""
    echo -e "${C_BOLD}2. (Optional) Shell Wrapper for 'envseal load':${C_RESET}"
    echo -e "   To allow ${C_CYA}envseal load${C_RESET} to export variables directly into your current shell session,"
    echo -e "   add the following function to your shell configuration file:\n"

    case "$current_shell" in
        fish)
            echo -e "${C_BOLD}--- Fish configuration (~/.config/fish/config.fish) ---${C_RESET}"
            cat <<'EOF'
function envseal
    if test "$argv[1]" = "load"
        if contains -- --help $argv; or contains -- -h $argv
            command envseal $argv
        else
            eval (command envseal $argv)
        end
    else
        command envseal $argv
    end
end
EOF
            ;;
        *)
            echo -e "${C_BOLD}--- Bash / Zsh configuration (~/.bashrc or ~/.zshrc) ---${C_RESET}"
            cat <<'EOF'
envseal() {
    if [ "$1" = "load" ]; then
        for _arg in "$@"; do
            if [ "$_arg" = "--help" ] || [ "$_arg" = "-h" ]; then
                command envseal "$@"
                return
            fi
        done
        eval "$(command envseal "$@")"
    else
        command envseal "$@"
    fi
}
EOF
            ;;
    esac

    echo ""
    echo -e "${C_BOLD}3. Verify installation:${C_RESET}"
    echo -e "   ${C_CYA}$BIN_NAME --version${C_RESET}"
}

main "$@"
