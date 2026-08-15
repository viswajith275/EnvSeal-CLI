#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# envseal-cli Uninstaller (Linux & macOS)
# =============================================================================

readonly BIN_NAME="envseal"
readonly DEFAULT_INSTALL_DIR="$HOME/.local/bin"

# State
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
DRY_RUN=false
PURGE_RC=false

# UI & Colors
if [[ -t 1 ]]; then
    readonly C_RED='\033[0;31m'
    readonly C_GRN='\033[0;32m'
    readonly C_BLU='\033[0;34m'
    readonly C_YEL='\033[1;33m'
    readonly C_BOLD='\033[1m'
    readonly C_RESET='\033[0m'
else
    readonly C_RED='' C_GRN='' C_BLU='' C_YEL='' C_BOLD='' C_RESET=''
fi

log_info()    { echo -e "${C_BLU}==>${C_RESET} $*" >&2; }
log_success() { echo -e "${C_GRN}✔${C_RESET} $*" >&2; }
log_warn()    { echo -e "${C_YEL}⚠${C_RESET} $*" >&2; }
log_error()   { echo -e "${C_RED}✖${C_RESET} $*" >&2; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
${C_BOLD}Usage:${C_RESET} uninstall.sh [options]

Uninstalls the ${BIN_NAME} binary and cleans up shell configurations.

${C_BOLD}Options:${C_RESET}
  -d, --dir <path>   Target install directory containing binary (default: $DEFAULT_INSTALL_DIR)
  --purge-rc         Remove PATH lines and custom envseal wrapper functions from RC files
  --dry-run          Preview changes without deleting or modifying files
  -h, --help         Show this help message

${C_BOLD}Examples:${C_RESET}
  ./uninstall.sh
  ./uninstall.sh --purge-rc
  ./uninstall.sh --dir /usr/local/bin
EOF
}

# --- Argument Parsing ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)    INSTALL_DIR="$2"; shift 2 ;;
            --purge-rc)  PURGE_RC=true; shift ;;
            --dry-run)   DRY_RUN=true; shift ;;
            -h|--help)   usage; exit 0 ;;
            *)           log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# --- Shell Detection ---
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

# --- Binary Removal ---
remove_binary() {
    local target="$INSTALL_DIR/$BIN_NAME"

    if [[ -f "$target" ]]; then
        if [[ "$DRY_RUN" == true ]]; then
            log_info "[Dry-run] Would remove binary at $target"
        else
            rm -f "$target"
            log_success "Removed binary from ${C_BOLD}$target${C_RESET}"
        fi
    else
        log_warn "Binary not found at $target (skipping)"
    fi
}

# --- Shell Config Cleanup ---
cleanup_shell_config() {
    local current_shell config_file
    current_shell="$(detect_shell)"
    config_file="$(get_shell_config_file "$current_shell")"

    # Gather known configuration files
    local config_files=()
    [[ -n "$config_file" && -f "$config_file" ]] && config_files+=("$config_file")

    # Add fallback standard dotfiles if present
    for extra_rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.config/fish/config.fish"; do
        if [[ -f "$extra_rc" && " ${config_files[*]} " != *" $extra_rc "* ]]; then
            config_files+=("$extra_rc")
        fi
    done

    for rc in "${config_files[@]}"; do
        local modified=false

        # Check if installer comments or paths exist
        if grep -qF "# Added by $BIN_NAME installer" "$rc" 2>/dev/null || \
           grep -qF "$BIN_NAME" "$rc" 2>/dev/null; then

            if [[ "$DRY_RUN" == true ]]; then
                log_info "[Dry-run] Would clean up PATH/wrapper configurations in $rc"
                continue
            fi

            local temp_rc
            temp_rc="$(mktemp)"

            if [[ "$PURGE_RC" == true ]]; then
                # Strip installer block and multi-line envseal shell function wrappers
                awk '
                    BEGIN { in_func = 0 }
                    /# Added by '"$BIN_NAME"' installer/ { getline; next }
                    /^(function )?'"$BIN_NAME"'(\(\))?[[:space:]]*\{?/ { in_func = 1 }
                    in_func {
                        if ($0 ~ /^}/ || $0 ~ /^end/) { in_func = 0 }
                        next
                    }
                    { print }
                ' "$rc" > "$temp_rc"
                modified=true
            else
                # Clean up installer-injected PATH entry
                awk '
                    /# Added by '"$BIN_NAME"' installer/ { getline; next }
                    { print }
                ' "$rc" > "$temp_rc"
                modified=true
            fi

            if [[ "$modified" == true ]]; then
                mv "$temp_rc" "$rc"
                log_success "Cleaned configuration entries in ${C_BOLD}$rc${C_RESET}"
            else
                rm -f "$temp_rc"
            fi
        fi
    done
}

# --- Main Entrypoint ---
main() {
    parse_args "$@"

    echo -e "${C_BOLD}Uninstalling ${BIN_NAME}...${C_RESET}"
    [[ "$DRY_RUN" == true ]] && log_warn "Running in DRY-RUN mode. No files will be modified."

    remove_binary
    cleanup_shell_config

    echo ""
    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry run complete. No files were altered."
    else
        log_success "${C_BOLD}Uninstallation complete!${C_RESET}"
        echo -e "Restart your terminal or reload your shell profile to apply changes."
    fi
}

main "$@"
