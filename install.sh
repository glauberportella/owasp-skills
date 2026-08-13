#!/usr/bin/env bash
#
# Installs OWASP security skills as symlinks into the skill directories
# read by Claude Code and OpenCode.
#
# Usage:
#   ./install.sh [--scope user|project] [--tool all|claude|opencode] [--copy] [--dest DIR] [skill ...]
#
# Examples:
#   ./install.sh                              # all skills, user scope, all tools
#   ./install.sh --scope project               # install into ./.claude/skills and ./.opencode/skills
#   ./install.sh owasp-top10-web owasp-api-security
#   ./install.sh --copy                         # copy files instead of symlinking

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$SCRIPT_DIR/skills"

SCOPE="user"
TOOL="all"
MODE="symlink"
DEST=""
SKILLS=()

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope)
      SCOPE="$2"; shift 2 ;;
    --tool)
      TOOL="$2"; shift 2 ;;
    --copy)
      MODE="copy"; shift ;;
    --dest)
      DEST="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      SKILLS+=("$1"); shift ;;
  esac
done

if [[ "$SCOPE" != "user" && "$SCOPE" != "project" ]]; then
  echo "error: --scope must be 'user' or 'project'" >&2
  exit 1
fi

if [[ "$TOOL" != "all" && "$TOOL" != "claude" && "$TOOL" != "opencode" ]]; then
  echo "error: --tool must be 'all', 'claude', or 'opencode'" >&2
  exit 1
fi

if [[ ! -d "$SKILLS_DIR" ]]; then
  echo "error: could not find skills/ directory next to install.sh ($SKILLS_DIR)" >&2
  exit 1
fi

if [[ ${#SKILLS[@]} -eq 0 ]]; then
  while IFS= read -r dir; do
    SKILLS+=("$(basename "$dir")")
  done < <(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)
fi

base_dir() {
  if [[ -n "$DEST" ]]; then
    echo "$DEST"
  elif [[ "$SCOPE" == "user" ]]; then
    echo "$HOME"
  else
    echo "$(pwd)"
  fi
}

BASE="$(base_dir)"

TARGET_DIRS=()
if [[ "$TOOL" == "all" || "$TOOL" == "claude" ]]; then
  TARGET_DIRS+=("$BASE/.claude/skills")
fi
if [[ "$TOOL" == "all" || "$TOOL" == "opencode" ]]; then
  TARGET_DIRS+=("$BASE/.opencode/skills")
fi

for target in "${TARGET_DIRS[@]}"; do
  mkdir -p "$target"
  for skill in "${SKILLS[@]}"; do
    src="$SKILLS_DIR/$skill"
    if [[ ! -d "$src" ]]; then
      echo "warning: skill '$skill' not found in $SKILLS_DIR, skipping" >&2
      continue
    fi
    dest="$target/$skill"
    if [[ -e "$dest" || -L "$dest" ]]; then
      rm -rf "$dest"
    fi
    if [[ "$MODE" == "symlink" ]]; then
      ln -s "$src" "$dest"
      echo "linked   $dest -> $src"
    else
      cp -R "$src" "$dest"
      echo "copied   $src -> $dest"
    fi
  done
done

echo
echo "Installed ${#SKILLS[@]} skill(s) into ${#TARGET_DIRS[@]} location(s)."
echo "Run ./uninstall.sh with the same --scope/--tool/--dest flags to remove them."
