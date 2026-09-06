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

INSTALL_DIR="$DEFAULT_INSTALL_DIR"
VERSION="$VERSION_DEFAULT"
LOCAL_FILE=""
DRY_RUN=false
SKIP_VERIFY=false

PLATFORM=""
TMP_DIR=""

# naive color override check
if [[ -t 1 || "${CLICOLOR_FORCE:-0}" == "1" ]]; then
    readonly C_RED=$'\033[0;31m'
    readonly C_GRN=$'\033[0;32m'
    readonly C_BLU=$'\033[0;34m'
    readonly C_YEL=$'\033[1;33m'
    readonly C_CYA=$'\033[0;36m'
    readonly C_BOLD=$'\033[1m'
    readonly C_RESET=$'\033[0m'
else
    readonly C_RED='' C_GRN='' C_BLU='' C_YEL='' C_CYA='' C_BOLD='' C_RESET=''
fi

log_step()    { printf "%b==>%b %b%s%b\n" "${C_BLU}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}" >&2; }
log_info()    { printf "%b  ->%b %s\n" "${C_CYA}" "${C_RESET}" "$*" >&2; }
log_success() { printf "%b  ✔%b %s\n" "${C_GRN}" "${C_RESET}" "$*" >&2; }
log_warn()    { printf "%b  !%b %s\n" "${C_YEL}" "${C_RESET}" "$*" >&2; }
log_error()   { printf "%b  ✖%b %s\n" "${C_RED}" "${C_RESET}" "$*" >&2; }

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

has_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
    local code="${1:-0}"
    cat <<EOF
${C_BOLD}Usage:${C_RESET} install.sh [options]

Installs the ${BIN_NAME} binary from GitHub Releases or a local archive.

${C_BOLD}Options:${C_RESET}
  -d, --dir <path>      Target install directory (default: ${DEFAULT_INSTALL_DIR})
  -v, --version <tag>   Release version to install (default: latest)
  -f, --file <path>     Install directly from a local archive or binary
  --no-verify           Skip SHA-256 checksum verification
  --dry-run             Preview actions without making changes
  -h, --help            Show this help message
EOF
    exit "$code"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)      [[ $# -lt 2 ]] && usage 1; INSTALL_DIR="$2"; shift 2 ;;
            -v|--version)  [[ $# -lt 2 ]] && usage 1; VERSION="$2"; shift 2 ;;
            -f|--file)     [[ $# -lt 2 ]] && usage 1; LOCAL_FILE="$2"; shift 2 ;;
            --no-verify)   SKIP_VERIFY=true; shift ;;
            --dry-run)     DRY_RUN=true; shift ;;
            -h|--help)     usage 0 ;;
            *)             log_error "Unknown option: $1"; usage 1 ;;
        esac
    done

    if [[ "$VERSION" != "latest" && "$VERSION" != v* ]]; then
        VERSION="v$VERSION"
    fi
}

http_get() {
    local url="$1"
    if has_cmd curl; then
        curl -fsSL "$url"
    elif has_cmd wget; then
        wget -qO- "$url"
    else
        log_error "curl or wget is required."
        exit 1
    fi
}

http_download() {
    local url="$1" dest="$2"
    if has_cmd curl; then
        if [[ -t 2 ]]; then
            curl -fL --progress-bar -o "$dest" "$url"
        else
            curl -fsSL -o "$dest" "$url"
        fi
    elif has_cmd wget; then
        if [[ -t 2 ]]; then
            wget -q --show-progress -O "$dest" "$url"
        else
            wget -q -O "$dest" "$url"
        fi
    else
        log_error "curl or wget is required."
        exit 1
    fi
}

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    is_musl() {
        [[ -f /lib/ld-musl-x86_64.so.1 || -f /lib/ld-musl-aarch64.so.1 ]] && return 0
        if has_cmd ldd && ldd --version 2>&1 | grep -qi musl; then return 0; fi
        [[ -f /etc/alpine-release ]]
    }

    case "$os" in
        Linux)
            case "$arch" in
                # assumes static musl binary runs on glibc x86_64
                x86_64|amd64) PLATFORM="linux-musl-x86_64" ;;
                aarch64|arm64)
                    if is_musl; then
                        log_error "musl aarch64 is not currently supported."
                        exit 1
                    fi
                    PLATFORM="linux-aarch64"
                    ;;
                *) PLATFORM="" ;;
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
        *) PLATFORM="" ;;
    esac

    if [[ -z "$PLATFORM" ]]; then
        log_error "Unsupported operating system/architecture: $os/$arch"
        exit 1
    fi
    log_info "Detected target: ${C_BOLD}$PLATFORM${C_RESET}"
}

verify_checksum() {
    local target_file="$1" sidecar_url="$2"
    if [[ "$SKIP_VERIFY" == true ]]; then
        return 0
    fi

    log_info "Verifying SHA-256 checksum..."
    local sidecar_content
    sidecar_content="$(http_get "$sidecar_url" 2>/dev/null || true)"
    if [[ -z "$sidecar_content" ]]; then
        log_warn "Checksum sidecar not found. Skipping verification."
        return 0
    fi

    local expected actual
    expected="$(echo "$sidecar_content" | awk '{print tolower($1); exit}')"
    if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
        log_warn "Malformed checksum file. Skipping verification."
        return 0
    fi

    if has_cmd sha256sum; then
        actual="$(sha256sum "$target_file" | awk '{print tolower($1)}')"
    elif has_cmd shasum; then
        actual="$(shasum -a 256 "$target_file" | awk '{print tolower($1)}')"
    else
        log_warn "No sha256sum/shasum utility found. Skipping verification."
        return 0
    fi

    if [[ "$expected" != "$actual" ]]; then
        log_error "Checksum mismatch! Expected $expected, got $actual."
        exit 1
    fi
    log_success "Checksum verified"
}

extract_archive() {
    local src="$1" dest="$2"
    case "$src" in
        *.tar.gz|*.tgz) tar -xzf "$src" -C "$dest" ;;
        *) cp "$src" "$dest/$BIN_NAME" && chmod +x "$dest/$BIN_NAME" ;;
    esac
}

install_binary() {
    local target="$INSTALL_DIR/$BIN_NAME"
    local source_archive=""

    if [[ -n "$LOCAL_FILE" ]]; then
        [[ ! -f "$LOCAL_FILE" ]] && { log_error "Local file not found: $LOCAL_FILE"; exit 1; }
        source_archive="$LOCAL_FILE"
        log_info "Source: local archive (${source_archive})"
    else
        local rel_path="download/$VERSION"
        [[ "$VERSION" == "latest" ]] && rel_path="latest/download"
        local dl_url="https://github.com/$REPO/releases/$rel_path/${BIN_NAME}-${PLATFORM}${ARCHIVE_EXT}"

        if [[ "$DRY_RUN" == true ]]; then
            log_info "[Dry-run] Would download ${C_CYA}${dl_url}${C_RESET}"
            log_info "[Dry-run] Would install binary to ${C_BOLD}${target}${C_RESET}"
            return 0
        fi

        log_step "Downloading ${BIN_NAME} (${VERSION})..."
        source_archive="$TMP_DIR/download${ARCHIVE_EXT}"
        if ! http_download "$dl_url" "$source_archive"; then
            log_error "Failed to download asset from ${dl_url}"
            exit 1
        fi
        verify_checksum "$source_archive" "${dl_url}.sha256"
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[Dry-run] Would unpack and install to ${C_BOLD}${target}${C_RESET}"
        return 0
    fi

    mkdir -p "$INSTALL_DIR"
    local extract_dir="$TMP_DIR/extracted"
    mkdir -p "$extract_dir"
    extract_archive "$source_archive" "$extract_dir"

    local binary_src
    binary_src="$(find "$extract_dir" -type f -name "$BIN_NAME" | head -n 1 || true)"
    if [[ -z "$binary_src" || ! -f "$binary_src" ]]; then
        log_error "Could not locate '$BIN_NAME' binary in archive."
        exit 1
    fi

    cp "$binary_src" "$target"
    chmod +x "$target"
    log_success "Binary installed at ${C_BOLD}$target${C_RESET}"
}

detect_shell() {
    local shell_bin=""
    if has_cmd ps; then
        shell_bin="$(ps -p "$PPID" -o comm= 2>/dev/null | tr -d '[:space:]-')"
        shell_bin="$(basename "$shell_bin" 2>/dev/null || true)"
    fi
    [[ -z "$shell_bin" ]] && shell_bin="$(basename "${SHELL:-bash}")"
    echo "$shell_bin"
}

get_shell_config_file() {
    case "$1" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash) [[ -f "$HOME/.bash_profile" ]] && echo "$HOME/.bash_profile" || echo "$HOME/.bashrc" ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        *)    echo "" ;;
    esac
}

update_path_in_config() {
    local current_shell config_file
    current_shell="$(detect_shell)"
    config_file="$(get_shell_config_file "$current_shell")"

    if [[ -z "$config_file" ]]; then
        log_warn "Shell '$current_shell' unrecognized. Add '$INSTALL_DIR' to PATH manually."
        return 0
    fi

    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]] || grep -qsF "$INSTALL_DIR" "$config_file" 2>/dev/null; then
        log_info "PATH configuration already present in ${C_BOLD}$config_file${C_RESET}"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[Dry-run] Would add '$INSTALL_DIR' to PATH in ${C_BOLD}$config_file${C_RESET}"
        return 0
    fi

    mkdir -p "$(dirname "$config_file")"
    touch "$config_file"

    if [[ "$current_shell" == "fish" ]]; then
        printf "\n# Added by %s installer\nfish_add_path \"%s\"\n" "$BIN_NAME" "$INSTALL_DIR" >> "$config_file"
    else
        printf "\n# Added by %s installer\nexport PATH=\"%s:\$PATH\"\n" "$BIN_NAME" "$INSTALL_DIR" >> "$config_file"
    fi
    log_success "Added ${C_BOLD}$INSTALL_DIR${C_RESET} to PATH in ${C_BOLD}$config_file${C_RESET}"
}

main() {
    parse_args "$@"
    TMP_DIR="$(mktemp -d)"

    log_step "Installing ${BIN_NAME}..."
    if [[ "$DRY_RUN" == true ]]; then
        log_warn "Running in DRY-RUN mode. No changes will be committed."
    fi

    detect_platform
    install_binary
    update_path_in_config

    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry run complete."
        return 0
    fi

    local current_shell config_file
    current_shell="$(detect_shell)"
    config_file="$(get_shell_config_file "$current_shell")"

    printf "\n%b✔ Installation successful!%b\n\n" "${C_GRN}${C_BOLD}" "${C_RESET}"
    echo -e "${C_BOLD}Next steps:${C_RESET}"
    if [[ -n "$config_file" ]]; then
        echo -e "  1. Reload shell:  ${C_CYA}source $config_file${C_RESET}"
    else
        echo -e "  1. Ensure ${C_CYA}$INSTALL_DIR${C_RESET} is exported in your shell's PATH."
    fi
    echo -e "  2. Test binary:   ${C_CYA}$BIN_NAME --version${C_RESET}"
}

main "$@"
