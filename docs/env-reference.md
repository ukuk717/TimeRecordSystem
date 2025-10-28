# Lambda／API Gateway 向け環境変数・Secrets 整理

| 区分 | 変数名 | 必須 | 説明 | 推奨保管場所 |
|------|--------|------|------|--------------|
| アプリ設定 | `APP_TIMEZONE` | 任意 (既定: `Asia/Tokyo`) | 勤怠ロジックのタイムゾーン。Lambda では `Asia/Tokyo` を維持。 | Systems Manager Parameter Store |
| アプリ設定 | `APP_BASE_URL` | 必須 | パスワードリセット等で生成する絶対 URL のホスト。API Gateway のカスタムドメインに合わせる。 | Parameter Store |
| アプリ設定 | `ALLOWED_HOSTS` | 任意 | ホワイトリスト化する `Host` ヘッダー（カンマ区切り）。 | Parameter Store |
| セッション | `SESSION_SECRET` | **必須** | `express-session` の署名シークレット。ローカル以外では必ず固定値を注入。 | **Secrets Manager** |
| セッション | `SESSION_STORE_DRIVER` | 任意 (既定: `knex`) | `knex`（RDS）、`dynamodb`、`memory` を切替。Lambda 本番では `knex` か `dynamodb` を推奨。 | Parameter Store |
| セッション | `SESSION_TABLE_NAME` | 任意 | `connect-session-knex` のテーブル名（既定: `sessions`）。 | Parameter Store |
| セッション | `SESSION_TTL_SECONDS` | 任意 | セッションの TTL（秒）。既定は 43200 (12 時間)。 | Parameter Store |
| セッション | `SESSION_PRUNE_INTERVAL_MS` | 任意 | `knex` ストアのクリーンアップ間隔（ミリ秒）。既定 600000。 | Parameter Store |
| セッション (DynamoDB) | `DYNAMODB_SESSION_TABLE` | 任意 | セッション保存先テーブル名。未指定時は `${DYNAMODB_TABLE_PREFIX}-sessions`。 | Parameter Store |
| セッション (DynamoDB) | `DYNAMODB_TABLE_PREFIX` | 任意 | セッション用テーブル接頭辞。ステージごとに分離したい場合に利用。 | Parameter Store |
| セッション (DynamoDB) | `DYNAMODB_SESSION_READ_CAPACITY` / `DYNAMODB_SESSION_WRITE_CAPACITY` | 任意 | プロビジョンドモード利用時の RC/WC。オンデマンドの場合は未設定。 | Parameter Store |
| セッション (DynamoDB) | `AWS_REGION` | **必須** | DynamoDB 利用時のリージョン。 | Parameter Store |
| セッション (DynamoDB) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | 任意 | Lambda に IAM ロールを付与する場合は不要。ローカル実行向け。 | Secrets Manager (ローカル用途は `.env` 可) |
| RDS 接続 | `DB_PROVIDER` | 任意 (既定: `postgres`) | `postgres` / `mysql2` を指定。ローカル開発でメモリ SQLite を使う場合は `sqlite`。 | Parameter Store |
| RDS 接続 | `DATABASE_URL` | 任意 | 接続文字列。設定時は個別の `DB_*` を上書き。 | Secrets Manager |
| RDS 接続 | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | `DATABASE_URL` 未設定時は **必須** | RDS (もしくは RDS Proxy) の接続情報。 | Secrets Manager |
| RDS 接続 | `DB_SSL`, `DB_SSL_REJECT_UNAUTHORIZED`, `DB_CA_CERT` | 任意 | SSL/TLS 設定。`DB_CA_CERT` には PEM 文字列を設定。 | Secrets Manager |
| RDS 接続 | `DB_POOL_MIN`, `DB_POOL_MAX`, `DB_POOL_IDLE_TIMEOUT_MS` | 任意 | Knex のコネクションプール設定。Lambda では `min=0`、`max=10` 程度が目安。 | Parameter Store |
| バックオフィス | `DEFAULT_PLATFORM_ADMIN_EMAIL`, `DEFAULT_PLATFORM_ADMIN_PASSWORD` | 推奨 | 初期プラットフォーム管理者の自動作成用。未設定ならスキップ。 | Secrets Manager |
| 動作モード | `NODE_ENV` | 任意 | `production` を指定すると Cookie `secure` が既定で有効に。 | 環境変数 |
| ローカル | `PORT` | 任意 | `npm start` (Express) のリッスンポート。 | ローカル `.env` |

## 設定・シークレット管理の推奨フロー
1. RDS 接続情報と `SESSION_SECRET` を AWS Secrets Manager の JSON シークレットに集約し、Lambda には「シークレット名」を環境変数として注入する（AWS SDK で参照）。
2. 非秘匿のパラメータ（`APP_BASE_URL`、`SESSION_TTL_SECONDS` 等）は Systems Manager Parameter Store にプレーンテキストで格納し、デプロイ時に `serverless.yml`／CDK から参照する。
3. Session store に DynamoDB を使う場合は、CloudFormation で TTL (`expiresAt`) 属性と必要な GSI を作成。環境変数には最終的なテーブル名のみを渡す。
4. ローカル開発では `.env.local` 等に最小限の変数（`DB_PROVIDER=sqlite`, `SESSION_STORE_DRIVER=memory` 等）を設定し、Secrets Manager を参照しない簡易モードで動作可能。

## CI/CD での取り扱い
- デプロイ前に `npm run migrate` 等で RDS スキーマをチェックする場合、CI 用 IAM ユーザーには RDS Proxy 経由の最小権限を付与。
- セキュアな値は環境変数に直接埋め込まず、`aws secretsmanager get-secret-value` でフェッチしてから `npm run deploy` に渡す。
- 監査用途として Parameter Store のカスタムタグ（例: `Environment=prod`, `Service=TimeRecordSystem`）を付与する。
