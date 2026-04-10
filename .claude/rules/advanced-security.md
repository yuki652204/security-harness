# 高度なセキュリティ規約

Spring Boot / Kubernetes / Argo CD 構成を前提とした拡張セキュリティガイドライン。
基本規約は `security.md` を参照。

---

## 1. WAF（Web Application Firewall）設定ガイドライン

### 必須ルールセット
- **OWASP Core Rule Set (CRS) 3.3以上**を有効にする
- SQLインジェクション・XSS・CSRF・RFI/LFI・コマンドインジェクション検出を必ずONにする
- Spring Boot アプリの場合、`/actuator/**` エンドポイントは必ず社内IPのみに制限する

### Kubernetes Ingress（nginx-ingress）でのWAF設定
```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/modsecurity-snippet: |
      SecRuleEngine On
      SecRequestBodyLimit 10485760
      SecRule REQUEST_HEADERS:Content-Type "text/xml" \
        "id:1,phase:1,deny,status:403,msg:'XML not allowed'"
    # レート制限（ブルートフォース対策）
    nginx.ingress.kubernetes.io/limit-rps: "20"
    nginx.ingress.kubernetes.io/limit-connections: "10"
```

### WAFの監視・チューニング
- 初期はDetectionモードで稼働し、誤検知がないことを確認してからPreventionモードに切り替える
- WAFログは毎日レビューし、誤検知ルールは個別にexcludeする
- カスタムルールは変更履歴をGitで管理する

---

## 2. インシデント対応手順（情報漏洩発生時のフロー）

### 検知〜初動（0〜1時間以内）
1. **検知**：アラート受信 or 報告受付
2. **初期評価**：影響範囲・漏洩データの種類・規模を確認
3. **エスカレーション**：セキュリティ責任者・経営層に即時報告
4. **証跡保全**：ログ・スナップショットを改ざんされないよう保存（削除・上書き禁止）

### 封じ込め（1〜4時間以内）
```bash
# 影響を受けたPodを即時隔離（Kubernetes）
kubectl cordon <node-name>
kubectl delete pod <pod-name> --grace-period=0

# 該当サービスのネットワークポリシーで外部通信を遮断
kubectl apply -f network-policy-deny-all.yaml

# Argo CDで問題のあるDeployを即時ロールバック
argocd app rollback <app-name> --revision <safe-revision>
```

5. **認証情報の無効化**：漏洩した可能性のあるAPIキー・JWTシークレット・DBパスワードを即座にローテーション
6. **影響ユーザーの強制ログアウト**：セッション・JWTを全無効化

### 調査・分析（4〜24時間以内）
7. **根本原因分析**：侵入経路・脆弱性の特定
8. **影響範囲の確定**：漏洩したデータの種類・件数・対象ユーザーの特定
9. **タイムライン作成**：いつから・何が起きたかを時系列で整理

### 通知・報告（法的要件に従う）
10. **個人情報保護委員会への報告**：個人データ漏洩時は72時間以内に届出（改正個人情報保護法）
11. **影響ユーザーへの通知**：漏洩内容・対処方法を誠実に通知
12. **社内関係部署への共有**：法務・PR・経営層・カスタマーサポートへ

### 復旧・再発防止
13. **修正・パッチ適用**：脆弱性を修正してからサービス再開
14. **再発防止策の実施**：WAFルール追加・監視強化・コードレビュー強化
15. **事後レビュー（ポストモーテム）**：再発防止策をドキュメント化してチームで共有

### 連絡先リスト（インシデント発生時に即座に連絡）
- セキュリティ責任者：インシデント検知後5分以内
- 経営層：重大インシデントは30分以内
- 法務担当：個人情報漏洩が疑われる場合は即時
- 個人情報保護委員会：72時間以内（義務）

---

## 3. 保存データの暗号化（AES-256）

### 基本方針
- **機密データ（個人情報・決済情報・トークン）は必ずAES-256で暗号化してDBに保存する**
- 暗号鍵はアプリケーションコードに直接書かず、Vault（HashiCorp Vault）から取得する
- 鍵のローテーションは90日ごとに実施する

### Spring Bootでの実装例
```java
// 暗号化サービス（AES-256-GCM推奨）
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
            byte[] iv = generateSecureIv();
            GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            // IV + 暗号文を結合してBase64エンコード
            byte[] combined = ByteBuffer.allocate(iv.length + encrypted.length)
                .put(iv).put(encrypted).array();
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new EncryptionException("暗号化に失敗しました", e);
        }
    }

    private byte[] generateSecureIv() {
        byte[] iv = new byte[12]; // GCMの推奨IV長は96bit
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
```

### Vault連携（Kubernetes環境）
```yaml
# Vault Agent Injectorを使って鍵をPodに注入
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

### 暗号化対象フィールド（必須）
| データ種別 | 暗号化要否 | 備考 |
|---|---|---|
| 氏名・生年月日 | 必須 | 個人情報 |
| メールアドレス | 必須 | 個人情報 |
| 電話番号 | 必須 | 個人情報 |
| 住所 | 必須 | 個人情報 |
| パスワード | BCryptハッシュ | 暗号化ではなくハッシュ化 |
| APIキー・トークン | 必須 | AES-256 |
| クレジットカード番号 | DBに保存禁止 | PCI DSS要件 |

---

## 4. PCI DSS準拠チェックリスト

クレジットカード情報を扱う場合に必須。Spring Boot / Kubernetes 環境での確認事項。

### ネットワークセキュリティ（要件1・2）
- [ ] カード情報を扱うPodはネットワークポリシーで隔離されている
- [ ] 不要なポートは全て閉じられている
- [ ] デフォルトパスワード・設定は全て変更済み
- [ ] `kubectl get networkpolicy` で隔離ポリシーが適用されていることを確認

### カードデータ保護（要件3・4）
- [ ] カード番号（PAN）をDBに平文で保存していない
- [ ] カード番号は決済代行サービス（Stripe / PayPay等）にのみ送り、自サーバーを通過させない（PCI DSS SAQ-A対応）
- [ ] 通信は全てTLS 1.2以上
- [ ] ログにカード番号・CVVを出力していない

### アクセス制御（要件7・8）
- [ ] カード情報へのアクセスは業務上必要な担当者のみに制限
- [ ] サービスアカウントは最小権限で設定
- [ ] MFA（多要素認証）を全管理者アカウントに適用
- [ ] Kubernetes RBACでカード情報Namespaceへのアクセスを制限

### 脆弱性管理（要件6）
- [ ] OWASP Dependency CheckをCIに組み込み済み
- [ ] Trivyでコンテナイメージをスキャン済み
- [ ] 重大な脆弱性（CVSS 7.0以上）は発見後30日以内にパッチ適用
- [ ] WAFが有効でOWASP CRSが適用されている

### 監視・ログ（要件10）
- [ ] カード情報へのアクセスログを全て記録
- [ ] ログは改ざん不可能な外部ストレージに保存（S3 Object Lock等）
- [ ] ログ保存期間は最低1年（直近3ヶ月はすぐ参照可能）
- [ ] 異常アクセスのアラートが設定されている

### 年次評価
- [ ] 年1回以上のペネトレーションテストを実施
- [ ] QSA（認定セキュリティ審査機関）によるPCI DSS評価を受ける（該当する場合）

---

## 5. ゼロトラスト基本設定

「信頼しない、常に検証する」の原則。社内ネットワーク内でも全通信を検証する。

### Kubernetes でのゼロトラスト実装

#### Pod間通信の制限（NetworkPolicy）
```yaml
# デフォルトで全通信を拒否し、必要な通信のみ許可
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# 特定のServiceへの通信のみ許可
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
```

#### mTLS（サービス間の相互TLS認証）
```yaml
# Istio / Linkerd でのmTLS強制
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # 全サービス間でmTLSを強制
```

### Spring Boot でのゼロトラスト実装

```java
// すべてのAPIエンドポイントで認証・認可を必須にする
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 全エンドポイントに認証を要求（ホワイトリスト方式）
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .anyRequest().authenticated()  // それ以外は全て認証必須
            )
            // JWTの検証を全リクエストで実施
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            // セッションを使わない（Stateless）
            .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
            // CSRF（Statelessなのでdisable可だが理由を明記）
            .csrf(csrf -> csrf.disable()); // JWT使用のためCSRFトークン不要
        return http.build();
    }
}
```

### Argo CD でのゼロトラスト設定

```yaml
# argocd-rbac-cm.yaml - 最小権限RBACポリシー
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.default: role:readonly  # デフォルトは読み取り専用
  policy.csv: |
    # 開発者：自分のNamespaceのみSync可能
    p, role:developer, applications, sync, development/*, allow
    p, role:developer, applications, get, development/*, allow

    # 本番デプロイは専用ロールのみ
    p, role:deployer, applications, sync, production/*, allow
    p, role:deployer, applications, get, *, allow

    # 管理者のみ全操作可能
    p, role:admin, *, *, *, allow

    # ロールの割り当て
    g, dev-team, role:developer
    g, deploy-team, role:deployer
```

### アクセスログの集中管理
- 全サービスのアクセスログをOpenTelemetry経由でLoki / Elasticsearch に集約
- 認証失敗・権限エラーは即時アラート（PagerDuty / Slack 連携）
- 異常なアクセスパターン（短時間の大量リクエスト等）を検知するルールを設定

---

## 6. Dependabot による自動依存関係更新

### Dependabotとは
GitHub が提供する依存関係の自動更新ツール。脆弱性のあるライブラリを自動検知し、
修正PRを自動で作成する。`.github/dependabot.yml` で設定する。

### 本プロジェクトの設定（`.github/dependabot.yml`）
| 対象 | 更新頻度 | 備考 |
|---|---|---|
| Maven（Javaライブラリ） | 毎週月曜 | Spring Boot等をグループ化 |
| GitHub Actions | 毎週月曜 | CIの安全性維持 |
| Docker | 毎週月曜 | ベースイメージの更新 |

### Dependabot PRの処理フロー
1. DependabotがPRを自動作成
2. CIが自動実行（セキュリティスキャン + テスト）
3. セキュリティアップデートは**優先的にレビュー・マージする**（翌営業日以内を目安）
4. メジャーバージョンアップは手動で動作確認してからマージ
5. セルフマージ禁止（security.md の規約に従う）

### セキュリティアラートへの対応
- GitHub Security Advisories でアラートが出たら**48時間以内**に対応する
- CVSS 9.0以上（Critical）は**即日対応**を原則とする
- Dependabotの自動PRが届いたら放置せず、1週間以内にマージまたはクローズする

### Dependabotを補完するツール
| ツール | 役割 | CIへの組み込み |
|---|---|---|
| OWASP Dependency Check | CVEデータベースと照合してJAR/warの脆弱性を検出 | security-ci.yml に組み込み済み |
| Trivy | コンテナイメージ・IaC設定の脆弱性スキャン | security-ci.yml に組み込み済み |
| Gitleaks | コミット履歴の機密情報スキャン | security-ci.yml に組み込み済み |
