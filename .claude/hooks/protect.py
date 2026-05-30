#!/usr/bin/env python3
"""
protect.py - PreToolUse フック
機密ファイルへの書き込みと危険なGit操作をブロックする
"""

import json
import re
import sys

# ブロック対象パターン（機密ファイル）
BLOCK_PATTERNS = [
    r'(^|/)\.env$',
    r'(^|/)\.env\.',
    r'.*\.pem$',
    r'.*\.key$',
]

# 例外パターン（allow-list）
ALLOW_PATTERNS = [
    r'\.env\.example$',
    r'\.env\.local\.example$',
    r'\.env\.template$',
    r'.*\.pubkey$',
]

# 危険なGitコマンド
BLOCKED_GIT_COMMANDS = [
    r'git\s+push\s+.*--force',
    r'git\s+push\s+.*-f\b',
    r'git\s+reset\s+--hard',
    r'git\s+clean\s+.*-f',
    r'git\s+rebase\s+.*--force',
]

try:
    data = json.load(sys.stdin)

    # === ファイルパスチェック ===
    target = data.get('path') or data.get('file_path') or ''

    if target:
        for allow in ALLOW_PATTERNS:
            if re.search(allow, target):
                sys.exit(0)

        for block in BLOCK_PATTERNS:
            if re.search(block, target):
                print(f"BLOCKED: {target}", file=sys.stderr)
                print(f"理由: 機密ファイルへのアクセスはブロックされています", file=sys.stderr)
                print(f"正当な作業の場合は .env.example を使うか、手動で編集してください", file=sys.stderr)
                sys.exit(2)

    # === Gitコマンドチェック ===
    command = data.get('command') or data.get('cmd') or ''

    if command:
        for pattern in BLOCKED_GIT_COMMANDS:
            if re.search(pattern, command):
                print(f"BLOCKED: {command}", file=sys.stderr)
                print(f"理由: 危険なGit操作はブロックされています", file=sys.stderr)
                print(f"必要な場合は手動でターミナルから実行してください", file=sys.stderr)
                sys.exit(2)

except Exception:
    pass

sys.exit(0)
