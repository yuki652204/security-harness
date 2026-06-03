#!/usr/bin/env python3
"""
protect.py - Claude Code PreToolUse 統合ガード
【役割1】機密ファイルへのアクセスをブロック
【役割2】不可逆な Git / DB 操作を deny / ask に振り分け
証跡: ~/.claude/protect-audit.log
"""
import json, os, re, sys
from datetime import datetime, timezone

AUDIT_LOG = os.path.expanduser("~/.claude/protect-audit.log")

SECRET_BLOCK = [r'(^|/)\.env$', r'(^|/)\.env\.', r'.*\.pem$', r'.*\.key$']
SECRET_ALLOW = [r'\.env\.example$', r'\.env\.local\.example$', r'\.env\.template$', r'.*\.pubkey$']

DENY_PATTERNS = [
    (r"git\s+push\b.*(--force(-with-lease)?|-f)\b.*\b(main|master)\b",
     "main/master への force push は共有履歴を破壊します。PR を経由してください。"),
    (r"git\s+push\b.*\b(main|master)\b.*(--force(-with-lease)?|-f)\b",
     "main/master への force push は共有履歴を破壊します。PR を経由してください。"),
    (r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b",
     "破壊的 SQL(DROP/TRUNCATE)を検知しました。環境と対象を人間が確認するまでブロックします。"),
    (r"rm\s+-[a-z]*r[a-z]*f?\b\s+(/|~|\$HOME)(\s|/|$)",
     "ルート/ホーム直下への rm -rf を検知しました。削除パスを限定してください。"),
]

ASK_PATTERNS = [
    (r"git\s+push\b.*(--force(-with-lease)?|-f)\b",
     "force push を検知しました。上書き対象を確認してから実行してください。"),
    (r"git\s+push\b.*\b(main|master)\b",
     "main/master への直接 push です。PR 経由が望ましいです。本当に実行しますか?"),
    (r"git\s+reset\s+--hard\b",
     "git reset --hard は未コミットの変更を失います。先に git stash を検討してください。"),
    (r"\b(rails\s+db:migrate|flyway\s+migrate|alembic\s+upgrade|prisma\s+migrate\s+deploy)\b",
     "DB マイグレーションを検知しました。対象環境を確認してください。"),
    (r"\bpsql\b.*\s+-f\b",
     "psql によるファイル直接実行を検知しました。中身と対象 DB を確認してください。"),
    (r"git\s+clean\s+-[a-z]*f",
     "git clean -f は追跡外ファイルを削除します。対象を確認してください。"),
]

def write_audit(decision, detail, reason):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": ts, "decision": decision, "detail": detail, "reason": reason}, ensure_ascii=False) + "\n")
    except Exception:
        pass

def emit(permission, reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": permission, "permissionDecisionReason": reason}}, ensure_ascii=False))
    sys.exit(0)

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool = data.get("tool_name", "")
    inp  = data.get("tool_input") or {}

    if tool in ("Edit", "Write", "Read", "MultiEdit"):
        target = inp.get("file_path") or inp.get("path") or ""
        if target:
            for allow in SECRET_ALLOW:
                if re.search(allow, target):
                    sys.exit(0)
            for block in SECRET_BLOCK:
                if re.search(block, target):
                    write_audit("deny", target, "機密ファイルへのアクセス")
                    print(f"BLOCKED: {target}", file=sys.stderr)
                    print("理由: 機密ファイルへのアクセスはブロックされています", file=sys.stderr)
                    print("正当な作業の場合は .env.example を使うか手動で編集してください", file=sys.stderr)
                    sys.exit(2)

    if tool == "Bash":
        command = inp.get("command", "")
        if not command:
            sys.exit(0)
        for pattern, reason in DENY_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                write_audit("deny", command, reason)
                emit("deny", "[protect.py BLOCK] " + reason)
        for pattern, reason in ASK_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                write_audit("ask", command, reason)
                emit("ask", "[protect.py CONFIRM] " + reason)

    sys.exit(0)

if __name__ == "__main__":
    main()
