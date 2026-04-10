# Security Harness Template

個人開発・チーム開発で使い回せるセキュリティハーネステンプレートです。
Claude Code と連携し、セキュリティ規約をプロジェクトに即座に適用できます。

---

## ファイル構成

```
security-harness/
├── .claude/
│   ├── rules/
│   │   └── security.md        # セキュリティ規約（Claude Codeが自動参照）
│   └── settings.json          # Claude Code の危険操作ブロック設定
├── .env.example               # 環境変数テンプレート（Git管理OK）
├── .gitignore                 # .env など機密ファイルの除外設定
└── README.md
```

---

## セキュリティ規約

### APIキーの扱い
- コードへのハードコード **禁止**
- 必ず `.env` 経由で読み込む
- `.env` を Git にコミット **禁止**
- GitHub に push してしまった場合は即座にキーを無効化・再発行する
- キーには最小権限のみ付与する

### バリデーション
- すべてのリクエストパラメータにバリデーションを実装する
- Controller では必ず `@Valid` または `@Validated` を付ける
- 数値は範囲チェック（`@Min` / `@Max`）、日付は過去・未来の制約を確認する

### 認証・認可
- パスワードは **BCrypt** でハッシュ化（平文保存禁止）
- JWT には必ず有効期限を設定する
- セッションタイムアウト・CSRF保護を有効にする
- 管理者機能には必ずロールチェックを入れる

### データベース（RLS）
- PostgreSQL を使う場合、テーブルには必ず **RLS（Row Level Security）** を有効にする
- 本番 DB への直接接続禁止（踏み台サーバー経由のみ）
- DB ユーザーには最小権限のみ付与する
- マイグレーションは必ずレビューしてから本番適用する

### コードレビュー・セキュリティ解析
- すべての PR は 1 名以上のレビューを受けてからマージする（セルフマージ禁止）
- CI に以下を組み込む：
  - **SpotBugs** — Javaバグ検出
  - **OWASP Dependency Check** — 依存ライブラリの脆弱性スキャン
  - **CodeRabbit** — AI コードレビュー
  - **Trivy** — コンテナ・IaC スキャン

### デプロイメント スキャン
- **Gitleaks** でコミット履歴の機密情報をスキャンする
- **Trivy** で Kubernetes マニフェストをスキャンする
- **Hadolint** で Dockerfile をチェックする
- 本番環境の認証情報は **Vault** から取得する
- Argo CD の RBAC ポリシーを最小権限で設定し、Admin パスワードは初回起動後すぐに変更する

### レート制限（ブルートフォース攻撃対策）
- ログイン失敗 **5回/分** でブロック → `429` を返す
- パスワードリセット **3回/時間** でブロック → `429` を返す

### HTTPS・セキュリティヘッダー
- 本番環境では HTTPS を強制する
- 以下のヘッダーを必ず設定する：

| ヘッダー | 値 |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000` |
| `Content-Security-Policy` | プロジェクトに合わせて設定 |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |

### ログ・監査証跡
- ログにパスワード・APIキー・カード番号・トークンを **出力しない**
- ログイン成功・失敗を必ず記録する
- 重要データの変更を記録する（日時・ユーザーID・変更内容）
- ログの保存期間は最低 **90日**
- MDC でユーザーID を全ログに付与する

---

## フィールド別バリデーション標準ルール

| フィールド | ルール |
|---|---|
| 名前（name） | 1〜50文字 |
| 電話番号（phone） | 10〜11桁・数字のみ |
| 住所（address） | 1〜200文字 |
| コメント・本文（text） | 1〜1000文字 |
| パスワード（password） | 8文字以上・英数字混在必須 |
| メールアドレス（email） | Email形式 |

---

## 使い方

### 新プロジェクトへの適用

1. このリポジトリをクローンまたはコピーする
2. `.claude/` ディレクトリをプロジェクトルートに配置する
3. `.env.example` をプロジェクトに合わせて編集する
4. `.gitignore` に `.env` が含まれていることを確認する

```bash
# 既存プロジェクトへの追加
cp -r security-harness/.claude /path/to/your-project/
cp security-harness/.env.example /path/to/your-project/
```

### Claude Code との連携

`.claude/rules/security.md` に置かれた規約は、Claude Code が会話のたびに自動で参照します。
これにより、コード生成・レビュー時に以下が自動適用されます：

- APIキーのハードコードを検出・拒否
- バリデーションアノテーションの自動提案
- セキュリティヘッダーの設定漏れを指摘
- SQLインジェクション・XSS リスクのある実装を警告

`.claude/settings.json` では、以下の危険なコマンドを Claude Code が実行できないようブロックしています：

```json
"denyTools": [
  "Bash(rm -rf*)",
  "Bash(git push --force*)",
  "Bash(DROP TABLE*)",
  "Bash(kubectl delete*)",
  ...
]
```

---

## 対応技術スタック

| カテゴリ | 技術 |
|---|---|
| バックエンド | Java 21 / Spring Boot 3.x |
| 認証 | Spring Security / JWT / Google OAuth2 |
| データベース | PostgreSQL（RLS対応） |
| 決済 | Stripe |
| メール | SMTP（Gmail等） |
| AI | Gemini API |
| コンテナ | Docker / Kubernetes |
| CI/CD | GitHub Actions / Argo CD |
| シークレット管理 | HashiCorp Vault |
| セキュリティスキャン | Trivy / Gitleaks / Hadolint / OWASP Dependency Check |

---

## チェックリスト

新プロジェクト開始時に確認してください。

### 初期設定
- [ ] `.env.example` をコピーして `.env` を作成した
- [ ] `.gitignore` に `.env` が含まれている
- [ ] APIキーをコードに直接書いていない
- [ ] すべての APIキーを環境変数経由で読み込んでいる

### 認証・認可
- [ ] パスワードを BCrypt でハッシュ化している
- [ ] JWT に有効期限を設定している
- [ ] CSRF 保護を有効にしている
- [ ] 管理者機能にロールチェックを入れている

### バリデーション
- [ ] すべての Controller に `@Valid` / `@Validated` を付けている
- [ ] フィールド別の文字数・形式チェックを実装している

### データベース
- [ ] PostgreSQL のテーブルに RLS を有効にしている
- [ ] DB ユーザーに最小権限のみ付与している
- [ ] マイグレーションをレビュー済み

### セキュリティヘッダー
- [ ] HTTPS を強制している（本番）
- [ ] HSTS を設定している
- [ ] CSP を設定している
- [ ] `X-Frame-Options: DENY` を設定している

### ログ
- [ ] ログにパスワード・APIキーを出力していない
- [ ] ログイン成功・失敗を記録している
- [ ] MDC でユーザーID を付与している

### CI/CD
- [ ] SpotBugs を CI に組み込んでいる
- [ ] OWASP Dependency Check を CI に組み込んでいる
- [ ] Trivy でコンテナスキャンをしている
- [ ] Gitleaks でコミット履歴をスキャンしている
- [ ] PR マージ前にレビューを受けている（セルフマージ禁止）
