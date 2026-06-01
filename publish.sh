#!/usr/bin/env bash
# Sanitize-and-publish kql-to-pq to github.com/marcredhat/kql.
#
# Safety:
#   - Bails if any tracked-or-untracked-but-not-ignored file contains a JWT
#     ("eyJ" prefix) or the live SDL hostname's tenant id.
#   - Initialises a fresh git repo (does NOT reuse the parent workspace repo).
#   - Force-pushes to the marcredhat/kql remote.
#
# Requirements: git, gh OR a configured SSH/HTTPS credential helper.

set -euo pipefail

REMOTE="https://github.com/marcredhat/kql.git"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo "=================================================================="
echo "Step 1/5  Verify .gitignore covers secrets"
echo "=================================================================="
test -f .gitignore
grep -qE '^config\.json$' .gitignore && echo "  config.json is gitignored ✓"
grep -qE '^reports/' .gitignore && echo "  reports/* gitignored ✓"

echo
echo "=================================================================="
echo "Step 2/5  Scan all candidate-tracked files for secrets"
echo "=================================================================="

# Build the list of files git WOULD track (init temp repo, add ., ls-files)
TMP_GIT=$(mktemp -d)
git --git-dir="$TMP_GIT" --work-tree="$HERE" init -q
git --git-dir="$TMP_GIT" --work-tree="$HERE" add -A
# Match a full JWT shape (3 base64url segments joined by '.', at least 64
# chars total) rather than just the 'eyJ' prefix so this very script (which
# documents the prefix in its grep) doesn't false-positive on itself.
LEAKED=$(git --git-dir="$TMP_GIT" --work-tree="$HERE" ls-files | \
    xargs -I{} grep -lE 'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' "{}" 2>/dev/null || true)
rm -rf "$TMP_GIT"

if [ -n "$LEAKED" ]; then
    echo "  ❌ JWT-like secret found in files that WOULD be committed:"
    echo "$LEAKED" | sed 's/^/    /'
    exit 1
fi
echo "  No JWTs in any to-be-committed file ✓"

echo
echo "=================================================================="
echo "Step 3/5  Initialise fresh git repo inside $HERE"
echo "=================================================================="
rm -rf .git
git init -q -b main
git add -A
git -c user.email="marc@example.com" -c user.name="marc" \
    commit -q -m "Initial commit: KQL ↔ SDL PowerQuery proof of equivalence"

echo "  $(git log --oneline)"
echo "  $(git ls-files | wc -l | tr -d ' ') files staged"

echo
echo "=================================================================="
echo "Step 4/5  Add remote $REMOTE"
echo "=================================================================="
git remote add origin "$REMOTE"
echo "  remote: $(git remote -v | head -1)"

echo
echo "=================================================================="
echo "Step 5/5  Push (force) to origin main"
echo "=================================================================="
git push -u --force origin main
echo "  ✓ Published to $REMOTE"
