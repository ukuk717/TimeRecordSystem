# 本番導入前に必ず実施する作業

## Secrets / 環境変数
- `SESSION_SECRET`、`DEFAULT_PLATFORM_ADMIN_EMAIL`、`DEFAULT_PLATFORM_ADMIN_PASSWORD`、`MFA_RESET_LOG_ENCRYPTION_KEY` は **AWS Secrets Manager** で管理し、CI/CD から Lambda（もしくはコンテナ）へ注入する。リポジトリや `.env` には開発用のみに留める。
- `MFA_RESET_LOG_ENCRYPTION_KEY` は 32 バイト以上のランダム値を hex もしくは base64 で生成し、ローテーション手順（発行 → デプロイ → 旧キー破棄）を Runbook 化する。
- `.env` でしか設定していない値は Parameter Store (SecureString) 経由で読み込むよう CD 設定を更新する。

## セッションストア
- **選定基準**
  - `knex` (PostgreSQL/MySQL) は強整合＆トランザクション保証が必要な場合や既存の RDS 運用チームがある場合に選択。AutoVacuum やインデックスサイズを監視できることが前提。
  - `dynamodb` はスケールアウト優先（マルチ AZ / serverless）で、多少の最終整合性と TTL での自動削除を許容できる場合に選択。ただしセッションキーが一箇所に集中する構造ではホットパーティション化するので、Partition key の分散設計（例: `sessionId` のハッシュ）と WCU/RCU の余裕を必ず確保する。
  - 「RDS から Dynamo」「Dynamo から RDS」などの移行は、**両ストアへの二重書き期間** と **カットオーバー時の TTL 確認** を経て実施する。どちらも `SESSION_SECRET` 共有を前提にしているため、暗号化/Cookie 設定が一致しているかを事前にチェックする。
- **安全な移行手順 (例: RDS → DynamoDB)**
  1. DynamoDB テーブルを新規作成 (`DYNAMODB_SESSION_TABLE`, TTL=expiresAt, AutoScaling or Provisioned Capacity を設定)。
  2. アプリ側にフィーチャーフラグを設け、数日間は **書き込み: RDS+Dyn** / **読み込み: RDS優先→なければDyn** にする。
  3. 両方のメトリクスを監視し、整合性が取れていることを `COUNT(*)` と TTL の差分で確認。
  4. カットオーバー当日、読み取りも Dynamo 優先に切り替え、RDS の TTL を短縮して自然消滅させる。逆方向も同様の段階的切り替えが必要。
- Knex 利用時は `sessions` テーブル作成と `SESSION_TABLE_NAME` の整合性を確認し、RDS Proxy 経由で接続テストを行う。
- DynamoDB 利用時は `DYNAMODB_SESSION_TABLE`・`DYNAMODB_TABLE_PREFIX`・RCU/WCU を環境変数に設定し、TTL 属性を `expiresAt` に揃える。最終整合性の読み取りでレイテンシがシビアな場合は `ConsistentRead=True` を設定する（コスト増に注意）。


## MFA リセットログ
- 平文で保存されている既存ログが本番データに混在しないよう、リリース直後に監査テーブル `tenant_admin_mfa_reset_logs` を確認し、暗号化済み形式へ移行していることを確認する（`previous_*` が base64 文字列になっているかで判別）。
- `MFA_RESET_LOG_ENCRYPTION_KEY` を本番値に差し替えた後は、ログ復号ができることをステージングで確認する。

## DB スキーマ
- `tenant_admin_mfa_reset_logs` を含む既存テーブルの `created_at` / `rolled_back_at` が string 型のままなので、TIMESTAMPTZ へ変換するマイグレーションを本番前に追加する（`docs/db-migration.md` 参照）。
- 変換マイグレーションはステージングで実行時間を測定し、バックアップ → マイグレーション → ロールバック手順をまとめる。

## 確認・運用
- 本番環境で `SESSION_STORE_DRIVER` を切り替えた後は、同時ログイン・セッションタイムアウトの挙動を必ず手動確認する。
- プラットフォーム管理者の 2FA リセット・ロールバックをステージングで一度実行し、暗号化ログが復元できることを証跡として残す。
