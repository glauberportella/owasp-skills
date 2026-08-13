#!/usr/bin/env bash
#
# Removes symlinks created by install.sh. Only removes entries that are
# symlinks pointing back into this repo's skills/ directory (or, with
# --copy, plain directories that match a known skill name) — never touches
# unrelated skills that happen to share the target directory.
#
# Usage:
#   ./uninstall.sh [--scope user|project] [--tool all|claude|opencode] [--copy] [--dest DIR] [skill ...]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$SCRIPT_DIR/skills"

SCOPE="user"
TOOL="all"
MODE="symlink"
DEST=""
SKILLS=()

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
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)
      SKILLS+=("$1"); shift ;;
  esac
done

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

removed=0
for target in "${TARGET_DIRS[@]}"; do
  for skill in "${SKILLS[@]}"; do
    dest="$target/$skill"
    src="$SKILLS_DIR/$skill"
    if [[ -L "$dest" ]]; then
      link_target="$(readlink "$dest")"
      if [[ "$link_target" == "$src" ]]; then
        rm "$dest"
        echo "removed  $dest"
        removed=$((removed + 1))
      else
        echo "skipped  $dest (symlink points elsewhere: $link_target)" >&2
      fi
    elif [[ -d "$dest" && "$MODE" == "copy" ]]; then
      rm -rf "$dest"
      echo "removed  $dest"
      removed=$((removed + 1))
    fi
  done
done

echo
echo "Removed $removed entr$([ "$removed" -eq 1 ] && echo y || echo ies)."
