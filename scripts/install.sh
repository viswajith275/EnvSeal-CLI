#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# envseal-cli Installer
#
# This script downloads and installs the envseal binary from GitHub Releases,
# or installs it from a local file/archive.
#
# Supported Environments:
#   - Linux (x86_64, aarch64)
#   - macOS (arm64 / Apple Silicon only)
#   - Windows (via Git Bash, MSYS2, Cygwin)
#
# Key Features:
#   - Auto-detects OS and Architecture.
#   - Verifies downloaded release archives against the SHA-256 checksum
#     published alongside each asset (skips gracefully if unavailable).
#   - Automatically adds the install directory to the user's PATH.
#   - Injects a shell wrapper function to allow `envseal load` to modify
#     the parent shell's environment variables using `eval`, while safely
#     ignoring help flags.
# =============================================================================

# --- Configuration Defaults ---
readonly REPO="viswajith275/envseal-cli"
readonly BIN_NAME="envseal"
readonly DEFAULT_INSTALL_DIR="$HOME/.local/bin"
readonly VERSION_DEFAULT="latest"

# --- Mutable Script State ---
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
VERSION="$VERSION_DEFAULT"
LOCAL_FILE=""
DRY_RUN=false
SKIP_VERIFY=false

# --- Dynamic Platform Variables ---
PLATFORM=""
EXE_EXT=""
ARCHIVE_EXT=".tar.gz"

# --- UI / Colors ---
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

# --- Logging Utilities ---
log_info() { echo -e "${GREEN}✓${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}⚠${NC} $*" >&2; }
log_error() { echo -e "${RED}✗${NC} $*" >&2; }

# --- Help / Usage Menu ---
usage() {
    cat <<EOF
Usage: install.sh [options]

Downloads and installs $BIN_NAME, or installs it from a local file.
Updates the current shell's configuration file if it exists.

Options:
  -d, --dir <path>      Install directory (default: $DEFAULT_INSTALL_DIR)
  -v, --version <tag>   Install a specific release tag (default: latest)
                          Example: v1.2.3 (the leading "v" is added
                          automatically if you omit it)
  -f, --file <path>     Manual install from local .tar.gz, .zip or binary
  --no-verify           Skip SHA-256 checksum verification of downloads
  --dry-run             Show what would be done without making changes
  -h, --help            Show this help message and exit

Examples:
  ./install.sh
  ./install.sh --version v1.2.3
  ./install.sh --version 1.2.3
  ./install.sh --dir /usr/local/bin
  ./install.sh --file ~/Downloads/$BIN_NAME-macos-aarch64.tar.gz
EOF
}

# --- Argument Parsing ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir) INSTALL_DIR="$2"; shift 2 ;;
            -v|--version) VERSION="$2"; shift 2 ;;
            -f|--file) LOCAL_FILE="$2"; shift 2 ;;
            --no-verify) SKIP_VERIFY=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    # Release tags are published as "v*" (see the release workflow),
    # so normalize a bare version like "1.2.3" to "v1.2.3".
    if [[ "$VERSION" != "latest" && "$VERSION" != v* ]]; then
        VERSION="v$VERSION"
    fi
}

# --- Dependency Checkers ---
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

fetch() {
    local url="$1"
    if command_exists curl; then
        curl -fsSL "$url"
    elif command_exists wget; then
        wget -qO- "$url"
    else
        log_error "Neither curl nor wget is installed. Cannot download files."
        exit 1
    fi
}

# Like fetch(), but deliberately does NOT fail on a non-2xx HTTP status.
# GitHub's API returns a JSON body (with a "message" field) even on 403/404
# responses, and callers need to inspect that body to tell "rate limited"
# apart from "release not found" apart from "genuinely unreachable". Using
# `curl -f` here would discard the body on any error status, making that
# inspection impossible -- so this is only for API calls whose response body
# matters; use fetch()/fetch_to_file() for downloading actual release assets.
fetch_api() {
    local url="$1"
    if command_exists curl; then
        curl -sSL "$url"
    elif command_exists wget; then
        wget -qO- "$url" 2>/dev/null || true
    else
        log_error "Neither curl nor wget is installed. Cannot download files."
        exit 1
    fi
}

# Download a URL to a file, returning non-zero (instead of aborting the whole
# script via set -e) so callers can treat a missing optional asset (like a
# checksum file) as "not available" rather than a hard failure.
fetch_to_file() {
    local url="$1" dest="$2"
    if command_exists curl; then
        curl -fsSL -o "$dest" "$url"
    elif command_exists wget; then
        wget -q -O "$dest" "$url"
    else
        log_error "Neither curl nor wget is installed. Cannot download files."
        exit 1
    fi
}

# --- Platform Detection ---
set_platform_vars() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64) PLATFORM="linux-musl-x86_64" ;;
                aarch64|arm64) PLATFORM="linux-aarch64" ;;
                *) PLATFORM="" ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                arm64) PLATFORM="macos-aarch64" ;;
                x86_64) PLATFORM="" ;;
                *) PLATFORM="" ;;
            esac
            ;;
        CYGWIN*|MINGW*|MSYS*)
            EXE_EXT=".exe"
            ARCHIVE_EXT=".zip"
            case "$arch" in
                x86_64|amd64) PLATFORM="windows-x86_64" ;;
                *) PLATFORM="" ;;
            esac
            ;;
        *) PLATFORM="" ;;
    esac

    if [[ -z "$PLATFORM" ]]; then
        if [[ "$os" == "Darwin" && "$arch" == "x86_64" ]]; then
            log_error "Intel Macs (macOS/x86_64) are no longer supported by prebuilt releases."
            log_error "Build from source, or install manually with: ./install.sh --file <path-to-binary-or-archive>"
        else
            log_error "Unsupported platform: $os/$arch"
            log_error "Install manually with: ./install.sh --file <path-to-binary-or-archive>"
        fi
        exit 1
    fi
}

# --- Shell Configuration Helpers ---

# Whether $1 is a shell name this installer knows how to configure. Kept in
# sync with the case in get_shell_config_path() below.
is_known_shell() {
    case "$1" in
        bash|zsh|fish|ksh|mksh|tcsh) return 0 ;;
        *) return 1 ;;
    esac
}

detect_current_shell() {
    local shell_name=""

    # Prefer the shell that is actually running this script (its parent
    # process) over $SHELL. $SHELL only reflects the user's configured
    # *login* shell, which can silently diverge from the shell they're
    # currently using -- e.g. `bash install.sh` run from an interactive zsh
    # session, or `curl ... | bash` piped from zsh -- in which case trusting
    # $SHELL would update the wrong rc file (.bashrc instead of .zshrc, or
    # vice versa).
    if command_exists ps; then
        shell_name=$(ps -p "$PPID" -o comm= 2>/dev/null | tr -d '[:space:]')
        # Login shells are often reported with a leading '-' (e.g. "-zsh").
        shell_name="${shell_name#-}"
        # Some platforms report a full path (e.g. "/usr/bin/zsh") rather
        # than a bare name.
        shell_name="$(basename "$shell_name" 2>/dev/null || true)"
    fi

    # Fall back to the configured login shell if parent-process detection
    # didn't work (no `ps`, PPID unavailable, or the parent isn't a shell
    # this installer recognizes -- e.g. the script was invoked from a
    # Makefile or another non-interactive wrapper).
    if [[ -z "$shell_name" ]] || ! is_known_shell "$shell_name"; then
        shell_name=$(basename "${SHELL:-/bin/bash}")
    fi

    echo "$shell_name"
}

get_shell_config_path() {
    local shell="$1"
    case "$shell" in
        bash) echo "$HOME/.bashrc" ;;
        zsh) echo "$HOME/.zshrc" ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        ksh|mksh) echo "$HOME/.kshrc" ;;
        tcsh) echo "$HOME/.tcshrc" ;;
        *) echo "" ;;
    esac
}

# --- Core Installation Logic ---
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

# Verify a file's SHA-256 checksum against a ".sha256" sidecar file
# (as produced by `sha256sum`/`shasum -a 256`). Returns:
#   0  - verified OK
#   1  - verification failed (checksum mismatch) -- caller should abort
#   2  - could not verify (no tool available or no checksum file) -- caller
#        should warn and continue, since verification is best-effort
verify_checksum() {
    local file="$1" sidecar_url="$2" tmp_dir="$3"

    if [[ "$SKIP_VERIFY" == true ]]; then
        return 2
    fi

    if ! command_exists sha256sum && ! command_exists shasum; then
        return 2
    fi

    local sidecar
    sidecar="$tmp_dir/$(basename "$file").sha256"
    if ! fetch_to_file "$sidecar_url" "$sidecar" 2>/dev/null; then
        return 2
    fi

    # The sidecar's recorded filename may not match our local path, so only
    # compare the hash (first field) rather than running sha256sum -c directly.
    local expected actual
    expected=$(awk '{print $1; exit}' "$sidecar")
    if [[ -z "$expected" ]]; then
        return 2
    fi

    if command_exists sha256sum; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    fi

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        return 1
    fi
}

install_from_local() {
    if [[ ! -e "$LOCAL_FILE" ]]; then
        log_error "File not found: $LOCAL_FILE"
        exit 1
    fi

    local target_path="$INSTALL_DIR/${BIN_NAME}${EXE_EXT}"
    local tmp_dir
    tmp_dir=$(mktemp -d) || exit 1
    # Double-quoted here so $tmp_dir's value is baked into the trap string
    # immediately. A single-quoted trap would defer expansion to when the
    # trap actually fires (script exit) -- by which point this function's
    # `local tmp_dir` is out of scope, and `set -u` would abort with
    # "unbound variable" instead of cleaning up.
    # shellcheck disable=SC2064  # intentional: expand $tmp_dir now, not at signal time
    trap "rm -rf '$tmp_dir'" EXIT

    case "$LOCAL_FILE" in
        *.tar.gz|*.tgz)
            log_info "Installing from tar archive: $LOCAL_FILE"

            if ! tar -xzf "$LOCAL_FILE" -C "$tmp_dir" 2>/dev/null; then
                log_error "Failed to extract archive: $LOCAL_FILE"
                exit 1
            fi
            ;;
        *.zip)
            log_info "Installing from zip archive: $LOCAL_FILE"

            if ! command_exists unzip; then
                log_error "'unzip' command is required to extract .zip archives. Please install it first."
                exit 1
            fi

            if ! unzip -q "$LOCAL_FILE" -d "$tmp_dir" 2>/dev/null; then
                log_error "Failed to extract archive: $LOCAL_FILE"
                exit 1
            fi
            ;;
        *)
            log_info "Installing from raw binary: $LOCAL_FILE"
            if [[ "$DRY_RUN" == false ]]; then
                cp "$LOCAL_FILE" "$target_path"
                chmod +x "$target_path"
            fi
            log_info "Binary installed to: $target_path"
            return
            ;;
    esac

    local found_bin
    found_bin=$(find "$tmp_dir" -maxdepth 2 -type f -name "${BIN_NAME}*" ! -name "*.txt" ! -name "*.md" ! -name "*.sha256" 2>/dev/null | head -n 1 || true)

    if [[ -z "$found_bin" ]]; then
        log_error "No '$BIN_NAME' binary found in archive"
        exit 1
    fi

    if [[ "$DRY_RUN" == false ]]; then
        cp "$found_bin" "$target_path"
        chmod +x "$target_path"
    fi

    log_info "Binary installed to: $target_path"
}

install_from_release() {
    local release_url
    log_info "Detected platform: $PLATFORM"

    local api_url
    if [[ "$VERSION" == "latest" ]]; then
        api_url="https://api.github.com/repos/$REPO/releases/latest"
    else
        api_url="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
    fi

    log_info "Fetching release information..."

    local api_response
    # `|| true` prevents a genuine connection failure (DNS, timeout, etc.)
    # from tripping `set -e` here; the emptiness check below turns that
    # case into the friendly error message instead of a silent abort.
    api_response=$(fetch_api "$api_url") || true
    if [[ -z "$api_response" ]]; then
        log_error "Failed to reach GitHub API. Check your network connection or try again later."
        exit 1
    fi

    # Use the POSIX [[:space:]] class instead of the GNU-only \s escape --
    # macOS ships BSD-derived grep, which doesn't understand \s.
    if echo "$api_response" | grep -qi '"message":[[:space:]]*"API rate limit exceeded'; then
        log_error "GitHub API rate limit exceeded. Try again later, or set GITHUB_TOKEN and retry."
        exit 1
    fi

    if echo "$api_response" | grep -qi '"message":[[:space:]]*"Not Found"'; then
        log_error "Release '$VERSION' was not found for $REPO."
        exit 1
    fi

    # Escape the archive extension's literal dot before using it in a
    # regex-based grep match against the asset URL.
    local archive_ext_re="${ARCHIVE_EXT//./\\.}"
    release_url=$(echo "$api_response" | grep -o "https://github.com/[^\"]*${PLATFORM}${archive_ext_re}" | head -n 1 || true)

    if [[ -z "$release_url" ]]; then
        log_error "Could not find release asset for $PLATFORM (version: $VERSION)"
        log_error "Install manually with: ./install.sh --file <path-to-binary-or-archive>"
        exit 1
    fi

    log_info "Downloading from: $release_url"

    local tmp_dir target_path
    tmp_dir=$(mktemp -d) || exit 1
    # See the matching comment in install_from_local() -- must stay
    # double-quoted so the path is baked in now, not resolved at exit time.
    # shellcheck disable=SC2064  # intentional: expand $tmp_dir now, not at signal time
    trap "rm -rf '$tmp_dir'" EXIT

    local downloaded_file
    downloaded_file="$tmp_dir/$(basename "$release_url")"
    if ! fetch_to_file "$release_url" "$downloaded_file"; then
        log_error "Failed to download release"
        exit 1
    fi

    # Best-effort checksum verification against the "<asset>.sha256" sidecar
    # published by the release workflow.
    #
    # IMPORTANT: with `set -e` active, calling verify_checksum as a bare
    # statement would abort the whole script the instant it returns 1 or 2 --
    # before this case statement ever ran. Capturing the status via `||`
    # keeps the overall command's exit status 0 so set -e doesn't fire.
    local checksum_status=0
    verify_checksum "$downloaded_file" "${release_url}.sha256" "$tmp_dir" || checksum_status=$?
    case "$checksum_status" in
        0) log_info "Checksum verified" ;;
        1)
            log_error "Checksum verification FAILED for $downloaded_file"
            log_error "The downloaded file may be corrupted or tampered with. Aborting."
            exit 1
            ;;
        2)
            if [[ "$SKIP_VERIFY" == true ]]; then
                log_warn "Skipping checksum verification (--no-verify)"
            else
                log_warn "Skipping checksum verification (no checksum tool or sidecar file available)"
            fi
            ;;
    esac

    if [[ "$ARCHIVE_EXT" == ".zip" ]]; then
        if ! command_exists unzip; then
            log_error "'unzip' command is required to extract Windows .zip releases. Please install it first."
            exit 1
        fi

        if ! unzip -q "$downloaded_file" -d "$tmp_dir"; then
            log_error "Failed to extract zip archive"
            exit 1
        fi
    else
        if ! tar -xzf "$downloaded_file" -C "$tmp_dir"; then
            log_error "Failed to extract release archive"
            exit 1
        fi
    fi

    local found_bin
    found_bin=$(find "$tmp_dir" -maxdepth 2 -type f -name "${BIN_NAME}*" ! -name "*.txt" ! -name "*.md" ! -name "*.sha256" 2>/dev/null | head -n 1 || true)

    if [[ -z "$found_bin" ]]; then
        log_error "No '$BIN_NAME' binary found in release"
        exit 1
    fi

    target_path="$INSTALL_DIR/${BIN_NAME}${EXE_EXT}"
    if [[ "$DRY_RUN" == false ]]; then
        cp "$found_bin" "$target_path"
        chmod +x "$target_path"
    fi

    log_info "Binary installed to: $target_path"
}

# --- Shell Integration Engine ---
update_shell_config() {
    local shell config_file
    shell=$(detect_current_shell)
    config_file=$(get_shell_config_path "$shell")

    if [[ -z "$config_file" ]]; then
        log_warn "Unsupported shell: $shell (no automatic config update)"
        return 0
    fi

    if [[ ! -f "$config_file" ]]; then
        log_warn "Shell config file not found: $config_file (skipping config update)"
        return 0
    fi

    log_info "Detected shell: $shell"

    local modified=false
    case "$shell" in
        fish) modified=$(update_fish_config "$config_file") ;;
        *) modified=$(update_posix_config "$config_file") ;;
    esac

    if [[ "$modified" == "true" ]]; then
        log_info "Updated shell configuration: $config_file"
    else
        log_info "Shell configuration already up-to-date: $config_file"
    fi
}

update_posix_config() {
    local config_file="$1"
    local modified=false

    if ! grep -q "$(printf '%s\n' "$INSTALL_DIR" | sed 's/[[\.*^$/]/\\&/g')" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "# Added by $BIN_NAME installer - Updates PATH for the CLI"
                echo "export PATH=\"$INSTALL_DIR:\$PATH\""
            } >> "$config_file"
        fi
        modified=true
    fi

    local marker="# >>> $BIN_NAME shell integration >>>"
    if ! grep -qF "$marker" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "$marker"
                echo "$BIN_NAME() {"
                echo "    if [ \"\$1\" = \"load\" ]; then"
                echo "        _envseal_help=0"
                echo "        for _arg in \"\$@\"; do"
                echo "            if [ \"\$_arg\" = \"--help\" ] || [ \"\$_arg\" = \"-h\" ]; then"
                echo "                _envseal_help=1"
                echo "                break"
                echo "            fi"
                echo "        done"
                echo "        if [ \"\$_envseal_help\" -eq 1 ]; then"
                echo "            command $BIN_NAME \"\$@\""
                echo "        else"
                echo "            eval \"\$(command $BIN_NAME \"\$@\")\""
                echo "        fi"
                echo "        unset _envseal_help _arg"
                echo "    else"
                echo "        # Pass all other commands directly to the binary."
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

update_fish_config() {
    local config_file="$1"
    local modified=false

    if ! grep -q "$(printf '%s\n' "$INSTALL_DIR" | sed 's/[[\.*^$/]/\\&/g')" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "# Added by $BIN_NAME installer - Updates PATH for the CLI"
                echo "fish_add_path $INSTALL_DIR"
            } >> "$config_file"
        fi
        modified=true
    fi

    local marker="# >>> $BIN_NAME shell integration >>>"
    if ! grep -qF "$marker" "$config_file" 2>/dev/null; then
        if [[ "$DRY_RUN" == false ]]; then
            {
                echo ""
                echo "$marker"
                echo "function $BIN_NAME"
                echo "    if test \"\$argv[1]\" = \"load\""
                echo "        if contains -- --help \$argv; or contains -- -h \$argv"
                echo "            command $BIN_NAME \$argv"
                echo "        else"
                echo "            eval (command $BIN_NAME \$argv)"
                echo "        end"
                echo "    else"
                echo "        # Standard pass-through"
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

# --- Post-Install Verification ---
verify_installation() {
    local binary_path="$INSTALL_DIR/${BIN_NAME}${EXE_EXT}"

    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found: $binary_path"
        return 1
    fi

    if [[ ! -x "$binary_path" ]]; then
        log_error "Binary is not executable: $binary_path"
        return 1
    fi

    local version_output=""
    if "$binary_path" --version >/dev/null 2>&1; then
        version_output=$("$binary_path" --version 2>&1)
    elif "$binary_path" -V >/dev/null 2>&1; then
        version_output=$("$binary_path" -V 2>&1)
    elif "$binary_path" version >/dev/null 2>&1; then
        version_output=$("$binary_path" version 2>&1)
    elif "$binary_path" --help >/dev/null 2>&1; then
        version_output=$("$binary_path" --help 2>&1 | head -n 1)
    else
        if command_exists file && file "$binary_path" | grep -iq "ELF\|Mach-O\|executable\|PE32"; then
            log_warn "Binary exists but couldn't verify execution (missing version/help flags)"
            log_info "Binary installed: $binary_path"
            return 0
        else
            log_warn "Binary exists but execution could not be verified"
            return 0
        fi
    fi

    if [[ -n "$version_output" ]]; then
        log_info "Binary verified: $binary_path"
        log_info "Version info: $(echo "$version_output" | head -n 1)"
    fi

    return 0
}

# --- Main Entry Point ---
main() {
    parse_args "$@"

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "DRY RUN MODE - no files or configs will be modified"
    fi

    echo ""
    log_info "Starting installation for $BIN_NAME..."

    set_platform_vars
    validate_install_dir

    if [[ -n "$LOCAL_FILE" ]]; then
        install_from_local
    else
        install_from_release
    fi

    update_shell_config

    if [[ "$DRY_RUN" == false ]]; then
        echo ""

        if verify_installation; then
            log_info "Installation successful!"
        else
            log_warn "Could not fully verify the installation."
        fi

        echo ""
        echo "Next steps:"
        echo "  1. Reload your shell configuration to apply changes:"
        echo "     source $(get_shell_config_path "$(detect_current_shell)")"
        echo ""
        echo "  2. Test the installation:"
        echo "     $BIN_NAME --version"
        echo ""
        echo "  3. Use the CLI to load your environment variables:"
        echo "     $BIN_NAME load <YOUR_KEYS>..."
    else
        echo ""
        log_info "Dry run complete - no changes were made."
    fi
}

main "$@"
