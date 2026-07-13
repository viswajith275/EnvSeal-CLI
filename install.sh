#!/usr/bin/env bash
set -e

# Configuration (defaults, can be overridden by flags below)
REPO="viswajith275/envfuse-cli"
BIN_NAME="envfuse"
INSTALL_DIR="$HOME/.local/bin"
VERSION="latest"      # a specific tag, e.g. "v1.2.3", or "latest"
LOCAL_FILE=""          # path to a local tarball or raw binary, for manual/offline installs

usage() {
    cat <<EOF
Usage: install.sh [options]

Downloads and installs $BIN_NAME, or installs it manually from a local file.

Options:
  -d, --dir <path>      Install directory (default: $HOME/.local/bin)
  -v, --version <tag>   Install a specific release tag instead of the latest (e.g. v1.2.3)
  -f, --file <path>     Manual install: skip downloading and install from a local
                         .tar.gz release archive or a raw, already-built binary
  -h, --help            Show this help message and exit

Examples:
  # normal install (auto-detects OS/arch, downloads latest release)
  ./install.sh

  # install a specific version
  ./install.sh --version v1.2.3

  # install to a custom directory
  ./install.sh --dir /usr/local/bin

  # manual install from a release tarball you already downloaded
  ./install.sh --file ~/Downloads/$BIN_NAME-macos-aarch64.tar.gz

  # manual install from a binary you built yourself (e.g. cargo build --release)
  ./install.sh --file ./target/release/$BIN_NAME
EOF
}

# 0. Parse flags
while [ $# -gt 0 ]; do
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
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

echo "Installing $BIN_NAME..."
mkdir -p "$INSTALL_DIR"

if [ -n "$LOCAL_FILE" ]; then
    # --------------------------------------------------------------
    # Manual install: use a file the user already has on disk instead
    # of hitting the network at all. Useful for offline machines,
    # CI artifacts, or a binary you just built locally.
    # --------------------------------------------------------------
    if [ ! -e "$LOCAL_FILE" ]; then
        echo "File not found: $LOCAL_FILE"
        exit 1
    fi

    case "$LOCAL_FILE" in
        *.tar.gz|*.tgz)
            echo "Installing from local archive: $LOCAL_FILE"
            TMP_DIR=$(mktemp -d)
            tar -xzf "$LOCAL_FILE" -C "$TMP_DIR"

            # The archive may contain "$BIN_NAME-<target>" (as produced by
            # the release workflow) or just "$BIN_NAME". Handle either.
            FOUND_BIN=$(find "$TMP_DIR" -type f -name "$BIN_NAME*" | head -n 1)
            if [ -z "$FOUND_BIN" ]; then
                echo "Could not find a '$BIN_NAME*' binary inside $LOCAL_FILE"
                rm -rf "$TMP_DIR"
                exit 1
            fi

            mv "$FOUND_BIN" "$INSTALL_DIR/$BIN_NAME"
            rm -rf "$TMP_DIR"
            ;;
        *)
            echo "Installing from local binary: $LOCAL_FILE"
            cp "$LOCAL_FILE" "$INSTALL_DIR/$BIN_NAME"
            ;;
    esac

    chmod +x "$INSTALL_DIR/$BIN_NAME"
    echo "Successfully installed $BIN_NAME to $INSTALL_DIR (manual install)"
else
    # --------------------------------------------------------------
    # Normal install: detect OS/arch and download the matching
    # release asset from GitHub.
    # --------------------------------------------------------------

    # 1. Detect OS and Architecture
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
        # Point all Linux distros (including Fedora) to the static musl binary
        TARGET="linux-musl-x86_64"
    elif [ "$OS" = "Darwin" ] && [ "$ARCH" = "x86_64" ]; then
        TARGET="macos-x86_64"
    elif [ "$OS" = "Darwin" ] && [ "$ARCH" = "arm64" ]; then
        TARGET="macos-aarch64"
    else
        echo "Unsupported OS/Arch: $OS/$ARCH"
        echo "You can still install manually with: ./install.sh --file <path-to-binary-or-tarball>"
        exit 1
    fi

    # 2. Fetch the release URL (latest, or a specific tag)
    if [ "$VERSION" = "latest" ]; then
        RELEASE_API_URL="https://api.github.com/repos/$REPO/releases/latest"
    else
        RELEASE_API_URL="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
    fi

    RELEASE_URL=$(curl -s "$RELEASE_API_URL" | grep "browser_download_url.*$TARGET.tar.gz" | cut -d '"' -f 4)

    if [ -z "$RELEASE_URL" ]; then
        echo "Could not find a release for $TARGET (version: $VERSION)"
        echo "You can also install manually with: ./install.sh --file <path-to-binary-or-tarball>"
        exit 1
    fi

    # 3. Download and extract
    TMP_DIR=$(mktemp -d)

    echo "Downloading from $RELEASE_URL..."
    curl -sL "$RELEASE_URL" | tar -xz -C "$TMP_DIR"

    mv "$TMP_DIR/$BIN_NAME-$TARGET" "$INSTALL_DIR/$BIN_NAME"
    chmod +x "$INSTALL_DIR/$BIN_NAME"
    rm -rf "$TMP_DIR"

    echo "Successfully installed $BIN_NAME to $INSTALL_DIR"
fi

# 4. Shell integration (bash + zsh)
#
# We touch both .bashrc and .zshrc regardless of the user's current
# $SHELL, since people often use one interactively but still source
# the other (e.g. scripts, su -, tmux, CI, etc).

PATH_STR="export PATH=\"$INSTALL_DIR:\$PATH\""
LOAD_FUNC_MARKER="# >>> $BIN_NAME shell integration >>>"
LOAD_FUNC_END="# <<< $BIN_NAME shell integration <<<"

update_rc_file() {
    local RC_FILE="$1"

    # Create the rc file if it doesn't exist yet
    touch "$RC_FILE"

    # --- PATH setup ---
    if ! grep -q "$INSTALL_DIR" "$RC_FILE" 2>/dev/null; then
        {
            echo ""
            echo "# Added by $BIN_NAME installer"
            echo "$PATH_STR"
        } >> "$RC_FILE"
        echo "Added $INSTALL_DIR to your PATH in $RC_FILE"
    else
        echo "$INSTALL_DIR is already in your PATH in $RC_FILE"
    fi

    # --- envfuse() wrapper function ---
    # Intercepts "$BIN_NAME load ..." and evals its output (so it can
    # export env vars / aliases / etc into the current shell). Every
    # other subcommand passes straight through to the real binary.
    # Always calls the binary via `command` so this can never recurse
    # into itself, even if something else also defines a function or
    # alias with the same name.
    if ! grep -qF "$LOAD_FUNC_MARKER" "$RC_FILE" 2>/dev/null; then
        {
            echo ""
            echo "$LOAD_FUNC_MARKER"
            echo "$BIN_NAME() {"
            echo "    if [ \"\$1\" = \"load\" ]; then"
            echo "        eval \"\$(command $BIN_NAME \"\$@\")\""
            echo "    else"
            echo "        command $BIN_NAME \"\$@\""
            echo "    fi"
            echo "}"
            echo "$LOAD_FUNC_END"
        } >> "$RC_FILE"
        echo "Added $BIN_NAME() shell function to $RC_FILE"
    else
        echo "$BIN_NAME() shell function already present in $RC_FILE"
    fi
}

update_rc_file "$HOME/.bashrc"
update_rc_file "$HOME/.zshrc"

echo ""
echo "Installation complete!"
echo "Run '$BIN_NAME load <KEYS>...' any time — it will automatically apply the output to your current shell."
echo "Restart your shell, or run one of the following to apply the changes now:"
echo "  source ~/.bashrc   # if you're using bash"
echo "  source ~/.zshrc    # if you're using zsh"