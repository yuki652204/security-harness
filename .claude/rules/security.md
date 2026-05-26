# セキュリティ規約

## 絶対禁止
- パスワード・APIキー・トークンをコードにハードコードしない
- APIキーは必ず環境変数経由で取得する（コード内に直接書いたら即アウト）
- .envファイルをGitにコミットしない
- ログにID・パスワード・カード番号・トークンを出力しない
- SQLを文字列結合で組み立てない（PreparedStatement / JPA必須）
- エラーメッセージにスタックトレースをそのまま返さない
- 未検証の入力値をそのままDBや外部サービスに渡さない

## APIキーの扱い（厳守）
- コードに直接書く → 絶対禁止
- GitHubにpushしてしまった場合 → 即座にキーを無効化・再発行する
- 必ず .env から読み込む形にする
- APIキーには必要最小限の権限のみ付与する（最小権限の原則）

## バリデーション（必須）
- すべてのリクエストパラメータにバリデーションを実装する
- Controllerでは必ず @Valid または @Validated を付ける
- 数値は範囲チェックを必ず行う（@Min / @Max）
- 日付は過去・未来の制約を必ず確認する

## フィールド別 文字数制限（標準ルール）
- 名前（name）: 1〜50文字
- 電話番号（phone）: 10〜11桁・数字のみ
- 住所（address）: 1〜200文字
- コメント・本文（text）: 1〜1000文字
- パスワード（password）: 8文字以上・英数字混在必須
- メールアドレス（email）: Email形式

## 認証・認可
- パスワードは BCrypt でハッシュ化（平文保存禁止）
- JWT の有効期限は必ず設定する
- セッションタイムアウトを設定する
- CSRF保護を有効にする
- 管理者機能には必ずロールチェックを入れる

## データベース設定
- PostgreSQLを使う場合、テーブルには必ずRLSを有効にする
- 本番DBへの直接接続は禁止（踏み台サーバー経由のみ）
- DBユーザーには最小権限のみ付与する
- マイグレーションは必ずレビューしてから本番適用する

### DB別 RLS対応状況

| DB | RLS対応 | 備考 |
|---|---|---|
| PostgreSQL | ネイティブ対応 | `CREATE POLICY` でテーブル単位に設定 |
| Supabase | 完全対応 | PostgreSQL基盤。`auth.uid()` でポリシー設定可能 |
| MySQL | 非対応 | アプリ層での代替実装が必須（下記参照） |
| SQLite | 非対応 | 開発・テスト用途のみ。本番使用禁止 |

### MySQLを使う場合のRLS代替手段（必須）
MySQLはRLS非対応のため、アプリケーション層で以下を必ず実装する：

- ServiceでユーザーIDフィルターを必ず実装する（クエリに `WHERE user_id = :userId` を常に付与）
- Spring Securityの `@AuthenticationPrincipal` でユーザーIDを取得する
- 他ユーザーのデータにアクセスできないことをテストで確認する（境界値テスト必須）

### Supabaseを使う場合
- PostgreSQL基盤のためRLS完全対応
- `auth.uid()` を使ったポリシーで行レベルのアクセス制御が可能
- テーブル作成時は必ず `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` を実行する

## コードレビュー・セキュリティ解析（必須）
- すべてのPRは必ず1名以上のレビューを受けてからマージする
- セルフマージ禁止
- CIにSpotBugs・OWASP Dependency Check・CodeRabbit・Trivyを組み込む
- スキャンが通らない限りマージ禁止

## デプロイメントプラットフォーム セキュリティスキャン（必須）
- Gitleaksでコミット履歴をスキャンする
- KubernetesマニフェストをTrivyでスキャンする
- DockerfileをHadolintでチェックする
- 本番環境の認証情報はVaultから取得する
- Argo CDのRBACポリシーを最小権限で設定する
- Argo CDのAdminパスワードは初回起動後すぐに変更する

## レート制限（ブルートフォース攻撃対策）
- ログイン・パスワードリセットには必ずレート制限を設ける
- ログイン失敗5回/分でブロック
- パスワードリセット3回/時間でブロック
- 429レスポンスを返す

## HTTPS強制・セキュリティヘッダー設定
- 本番環境では必ずHTTPSを強制する
- HSTSを設定する（max-age=31536000）
- CSPを設定する
- X-Frame-Options: DENYを設定する
- X-Content-Type-Optionsを設定する

## ログ・監査証跡の設定
- ログにパスワード・APIキーを出力しない
- ログイン成功・失敗を必ず記録する
- 重要データの変更を記録する（日時・ユーザーID・変更内容）
- ログの保存期間は最低90日
- MDCでユーザーIDを全ログに付与する

## 個人情報・決済情報
- クレジットカード番号をDBに保存しない
- 個人情報はマスキングしてログ出力する
- 不要になった個人情報は速やかに削除する

## AES-256暗号化（個人情報を扱う場合は必須）
- 氏名・住所・電話番号などの個人情報はDBに平文で保存せず、必ずAES-256で暗号化する
- 暗号化キーはコードにハードコードせず、Vaultから取得する
- 鍵のローテーションは90日ごとに実施する

### 暗号化必須フィールド一覧

| フィールド | 暗号化要否 | 備考 |
|---|---|---|
| 氏名・生年月日 | 必須 | 個人情報 |
| メールアドレス | 必須 | 個人情報 |
| 電話番号 | 必須 | 個人情報 |
| 住所 | 必須 | 個人情報 |
| パスワード | BCryptハッシュ | 暗号化ではなくハッシュ化 |
| APIキー・トークン | 必須 | AES-256 |
| クレジットカード番号 | DBに保存禁止 | PCI DSS要件 |

### Spring Boot での AES-256-GCM 実装例

```java
@Service
public class EncryptionService {

    // 鍵はVaultから取得（絶対にハードコードしない）
    @Value("${encryption.key}")
    private String encryptionKey;

    public String encrypt(String plaintext) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(encryptionKey);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            // GCMモードで認証付き暗号化（改ざん検知あり）
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12]; // GCMの推奨IV長は96bit
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            // IV + 暗号文を結合してBase64エンコード
            byte[] combined = ByteBuffer.allocate(iv.length + encrypted.length)
                .put(iv).put(encrypted).array();
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new EncryptionException("暗号化に失敗しました", e);
        }
    }
}
```

### Vault からの暗号化キー取得（Kubernetes 環境）

```yaml
# Vault Agent Injector を使って鍵を Pod に注入する
apiVersion: v1
kind: Pod
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "app-role"
    vault.hashicorp.com/agent-inject-secret-encryption-key: "secret/app/encryption-key"
spec:
  containers:
    - name: app
      env:
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: encryption-key
```

- Vault のパスは `secret/app/encryption-key` に格納する
- Spring Boot アプリは `${encryption.key}` で環境変数から読み込む
- ローカル開発時は `.env` に Base64エンコードしたダミーキーを設定し、`.env` は Git にコミットしない
## ファイルアクセス（ディレクトリトラバーサル対策）
- ファイル名に `../` が含まれる場合は即座に400エラーを返す
- ファイルパスは必ず BASE_DIR 内かどうか `canonicalPath` で検証する
- ユーザー入力をそのままファイルパスに文字列結合しない

```java
// 必ずこのパターンで実装する
if (filename.contains("..")) {
    return ResponseEntity.status(400).build();
}
File file = new File(BASE_DIR + filename);
if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
    return ResponseEntity.status(403).build();
}
```

## 認証・トークン検証
- `token == null` チェックだけでは不十分（任意の文字列が通過できる = 認証なしと同等）
- JWTの署名・有効期限を必ず検証する
- `jwtService.isValid(token)` のような実装を必須とする
- ワンタイムトークンを使う場合も使用済みフラグの管理を忘れない

```java
// ❌ 禁止
if (token == null) { return 401; }

// ✅ 必須
if (!jwtService.isValid(token)) { return 401; }
```
