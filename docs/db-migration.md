# 外部データベース移行設計

## 1. 現状整理
- 永続層は `better-sqlite3` を利用したローカル SQLite。Lambda ではストレージが揮発的で同時実行時にロック競合が起きやすい。
- セッションストアも `better-sqlite3-session-store` に依存し、`data/session-secret.txt` への書き込みでシークレットを管理している。
- アプリコードは同期 I/O 前提。モジュール初期化で `fs.mkdirSync` などを実行するため、Lambda の並列実行と相性が悪い。

## 2. 目標アーキテクチャ
- 主要ドメインデータ（テナント・ユーザー・勤怠実績）はリレーショナル整合性が不可欠なので RDS（PostgreSQL または MySQL）を第一候補とする。
- セッションやワンタイムトークンなど高頻度アクセスは DynamoDB に配置し、スケールとレイテンシを最適化する二層構成を想定。
- Lambda + API Gateway を前提に、接続プールの再利用と Secrets Manager/Parameter Store による設定管理を標準化する。

## 3. RDS（PostgreSQL）スキーマ概要

| テーブル | 主キー | 主なカラム | 備考 |
|----------|--------|------------|------|
| tenants | id (SERIAL) | tenant_uid (UUID など), name, contact_email, created_at (TIMESTAMPTZ) | tenant_uid は UNIQUE |
| users | id (SERIAL) | tenant_id (FK), username, email (UNIQUE), password_hash, role, must_change_password, failed_attempts, locked_until, first_name, last_name, created_at | tenant_id は ON DELETE SET NULL |
| role_codes | id (SERIAL) | tenant_id (FK), code (UNIQUE), expires_at, max_uses, usage_count, is_disabled, created_by, created_at | code は 16 文字固定を推奨 |
| password_resets | id (SERIAL) | user_id (FK), token (UNIQUE), expires_at, used_at, created_at | token は ULID/UUID |
| work_sessions | id (SERIAL) | user_id (FK), start_time, end_time, created_at | (user_id, start_time) でインデックス |

### 推奨インデックス
- `users(email)`、`users(tenant_id, role)`、`work_sessions(user_id, start_time)`、`password_resets(token)`、`role_codes(code)`。

### 初期化フロー
1. 任意で `CREATE SCHEMA timerecord;` を実行し専用スキーマを用意。
2. 上記テーブルを同スキーマに作成し、必要な制約・インデックスを付与。
3. アプリ接続ユーザーには最小権限（USAGE + CRUD）を付与。Lambda からは RDS Proxy 経由で接続する。

## 4. DynamoDB 設計（セッション／トークン向け）
- **テーブル名**: `${prefix}-sessions` などの単一テーブル構成。
- **パーティションキー**: `pk`（例: `SESSION#<sessionId>`、`RESET#<token>`）。
- **ソートキー**: `sk`（例: 固定値 `META`）。
- **TTL 属性**: `expiresAt`（UNIX epoch 秒）。
- **GSI**: `entityType` + `tenantId` でアクティブセッションの一覧を取得できるようにする。
- Lambda からは `@aws-sdk/lib-dynamodb` を利用し、DocumentClient で扱いやすくする。

## 5. データ移行手順
1. メンテナンスウィンドウ中に書き込みを停止しバックアップ。
2. SQLite から各テーブルを CSV/JSON でエクスポート。
3. Node.js / Python の移行スクリプトで RDS に対してバルク挿入。トランザクションで整合性を担保。
4. ID を保持する場合は `setval()` などでシーケンスを調整。時系列データ（work_sessions 等）は昇順で投入。
5. 有効期限が短いセッションやロールコードは移行対象外としリセットするか、DynamoDB へ変換して投入する。

## 6. アプリケーション改修方針
- データアクセス層を `src/database` に切り出し、`DB_PROVIDER` で Sql（RDS）と将来の Dynamo 実装を切り替えられるようにする。
- すべてのデータ操作を `async/await` 化し、Express ルートで一元的にエラーハンドリング。
- セッションは `connect-session-knex`（RDS）または `connect-dynamodb` を採用。ローカル開発向けに `MemoryStore` も残す。
- Lambda のコールドスタート対策として、初期化処理と接続プールをグローバルスコープに保持。
- ファイルシステム依存（セッションシークレットのファイル保存など）は排除し、環境変数/Secrets へ移行。

## 7. インフラと Secrets 管理
- Secrets Manager に `SESSION_SECRET`・RDS 接続情報・初期管理者資格情報を格納。
- Parameter Store には `APP_BASE_URL`、`SESSION_TTL_SECONDS` など非秘匿値を保存しデプロイ時に参照。
- RDS Proxy + IAM 認証で Lambda から安全に接続。DynamoDB も IAM ロールでアクセス制御する。

## 8. フォローアップ
- 非同期化した DB レイヤーに合わせて Jest テストを刷新（現状は実行不可のため手動検証を併用）。
- CI/CD でマイグレーション実行（Knex migration 等）を自動化。
- 移行後の検証として件数チェックやチェックサム計算などの差分確認ツールを整備する。
