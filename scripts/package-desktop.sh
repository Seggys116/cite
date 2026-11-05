#!/bin/sh
# Package the unsigned Cite desktop app for one target OS.
set -eu

usage() {
  cat >&2 <<EOF
Usage: package-desktop.sh <target-os> <binary-path> <out-dir> <version>

  target-os    macos, linux or windows
  binary-path  built cite-desktop binary (cite-desktop.exe on windows)
  out-dir      directory that receives the archive and its .sha256 file
  version      version string used in file names, for example 0.2.0
EOF
  exit 2
}

die() {
  printf 'package-desktop: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

write_checksum() {
  (cd "$(dirname "$1")" && sha256_file "$(basename "$1")" >"$(basename "$1").sha256")
}

[ $# -eq 4 ] || usage

TARGET_OS=$1
BINARY=$2
OUT_DIR=$3
VERSION=$4

case $TARGET_OS in
  macos|linux|windows) ;;
  *) die "unknown target-os: $TARGET_OS (use macos, linux or windows)" ;;
esac

case $VERSION in
  [0-9]*) ;;
  *) die "version must start with a digit: $VERSION" ;;
esac
case $VERSION in
  *[!0-9A-Za-z.+-]*) die "version contains unexpected characters: $VERSION" ;;
esac

[ -f "$BINARY" ] || die "binary not found: $BINARY"
[ -x "$BINARY" ] || [ "$TARGET_OS" = windows ] || die "binary is not executable: $BINARY"

mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/cite-desktop.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

case $TARGET_OS in
  macos)
    APP="$STAGE/Cite.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    cp "$BINARY" "$APP/Contents/MacOS/cite-desktop"
    chmod 755 "$APP/Contents/MacOS/cite-desktop"
    cat >"$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>Cite</string>
  <key>CFBundleDisplayName</key>
  <string>Cite</string>
  <key>CFBundleIdentifier</key>
  <string>dev.seggys116.cite</string>
  <key>CFBundleExecutable</key>
  <string>cite-desktop</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF
    ARCHIVE="$OUT_DIR/Cite-$VERSION-macos-$(uname -m).zip"
    rm -f "$ARCHIVE"
    ditto -c -k --keepParent "$APP" "$ARCHIVE"
    ;;
  linux)
    PKG="cite-desktop-$VERSION-linux-$(uname -m)"
    mkdir -p "$STAGE/$PKG"
    cp "$BINARY" "$STAGE/$PKG/cite-desktop"
    chmod 755 "$STAGE/$PKG/cite-desktop"
    cat >"$STAGE/$PKG/cite.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Cite
Comment=Cite node and site manager
Exec=cite-desktop
Terminal=false
Categories=Network;Utility;
EOF
    cat >"$STAGE/$PKG/README.txt" <<EOF
Cite desktop $VERSION (unsigned build). Put cite-desktop on your PATH and copy cite.desktop to ~/.local/share/applications/.
EOF
    ARCHIVE="$OUT_DIR/$PKG.tar.gz"
    tar -C "$STAGE" -czf "$ARCHIVE" "$PKG"
    ;;
  windows)
    PKG="cite-desktop-$VERSION-windows-x86_64"
    mkdir -p "$STAGE/$PKG"
    cp "$BINARY" "$STAGE/$PKG/cite-desktop.exe"
    ARCHIVE="$OUT_DIR/$PKG.zip"
    rm -f "$ARCHIVE"
    if command -v 7z >/dev/null 2>&1; then
      (cd "$STAGE" && 7z a -tzip "$ARCHIVE" "$PKG" >/dev/null)
    elif command -v zip >/dev/null 2>&1; then
      (cd "$STAGE" && zip -qr "$ARCHIVE" "$PKG")
    else
      die "neither 7z nor zip is available to build the archive"
    fi
    ;;
esac

write_checksum "$ARCHIVE"
printf 'wrote %s and %s.sha256\n' "$ARCHIVE" "$ARCHIVE"
if [ "$TARGET_OS" = macos ]; then
  printf 'note: this build is unsigned and not notarised; Gatekeeper needs right-click Open on first launch.\n'
fi
