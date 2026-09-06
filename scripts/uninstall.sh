#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# envseal-cli Uninstaller (Linux & macOS)
# =============================================================================

readonly BIN_NAME="envseal"
readonly DEFAULT_INSTALL_DIR="$HOME/.local/bin"

INSTALL_DIR="$DEFAULT_INSTALL_DIR"
DRY_RUN=false
PURGE_RC=false

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

usage() {
    local code="${1:-0}"
    cat <<EOF
${C_BOLD}Usage:${C_RESET} uninstall.sh [options]

Uninstalls the ${BIN_NAME} binary and cleans up shell configurations.

${C_BOLD}Options:${C_RESET}
  -d, --dir <path>   Target install directory containing binary (default: ${DEFAULT_INSTALL_DIR})
  --purge-rc         Remove PATH lines and custom envseal wrapper functions from RC files
  --dry-run          Preview changes without deleting or modifying files
  -h, --help         Show this help message
EOF
    exit "$code"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)    [[ $# -lt 2 ]] && usage 1; INSTALL_DIR="$2"; shift 2 ;;
            --purge-rc)  PURGE_RC=true; shift ;;
            --dry-run)   DRY_RUN=true; shift ;;
            -h|--help)   usage 0 ;;
            *)           log_error "Unknown option: $1"; usage 1 ;;
        esac
    done
}

remove_binary() {
    local target="$INSTALL_DIR/$BIN_NAME"
    if [[ -f "$target" ]]; then
        if [[ "$DRY_RUN" == true ]]; then
            log_info "[Dry-run] Would remove binary at ${C_BOLD}$target${C_RESET}"
        else
            rm -f "$target"
            log_success "Removed binary from ${C_BOLD}$target${C_RESET}"
        fi
    else
        log_warn "Binary not found at ${C_BOLD}$target${C_RESET} (skipping)"
    fi
}

cleanup_rc() {
    # inspects static candidate list rather than active shell AST
    local candidates=(
        "$HOME/.bashrc"
        "$HOME/.bash_profile"
        "$HOME/.zshrc"
        "$HOME/.config/fish/config.fish"
    )

    for rc in "${candidates[@]}"; do
        [[ -f "$rc" ]] || continue
        grep -qsF "$BIN_NAME" "$rc" || continue

        if [[ "$DRY_RUN" == true ]]; then
            log_info "[Dry-run] Would clean up entries in ${C_BOLD}$rc${C_RESET}"
            continue
        fi

        local temp_rc
        temp_rc="$(mktemp)"

        # regex-based function deletion assumes unindented closing brace
        if [[ "$PURGE_RC" == true ]]; then
            awk -v b="$BIN_NAME" '
                BEGIN { in_func = 0 }
                $0 ~ ("# Added by " b " installer") { getline; next }
                $0 ~ ("^(function )?" b "(\\(\\))?[[:space:]]*\\{?") { in_func = 1 }
                in_func {
                    if ($0 ~ /^}/ || $0 ~ /^end/) { in_func = 0 }
                    next
                }
                { print }
            ' "$rc" > "$temp_rc"
        else
            awk -v b="$BIN_NAME" '
                $0 ~ ("# Added by " b " installer") { getline; next }
                { print }
            ' "$rc" > "$temp_rc"
        fi

        # compare before touching to preserve timestamps when no changes occur
        if ! cmp -s "$temp_rc" "$rc"; then
            mv "$temp_rc" "$rc"
            log_success "Cleaned configuration entries in ${C_BOLD}$rc${C_RESET}"
        else
            rm -f "$temp_rc"
        fi
    done
}

main() {
    parse_args "$@"
    log_step "Uninstalling ${BIN_NAME}..."
    [[ "$DRY_RUN" == true ]] && log_warn "Running in DRY-RUN mode. No changes will be committed."

    remove_binary
    cleanup_rc

    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry run complete."
    else
        printf "\n%b✔ Uninstallation complete!%b\n" "${C_GRN}${C_BOLD}" "${C_RESET}"
    fi
}

main "$@"
