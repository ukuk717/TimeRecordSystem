# テナント管理者 MFA リセット運用メモ

## 実装状況
- `20251110120000_add_tenant_admin_mfa_reset_logs.js` で保持する `previous_method_json` / `previous_recovery_codes_json` は、`src/app.js` の `encryptSensitiveLogPayload` を通じて **AES-256-GCM** で暗号化されたペイロード（`enc:<base64>` 形式）を保存するように更新済み。暗号化キーはアプリ起動時に自己診断され、失敗した場合はプロセスが停止する。暗号化がどうしても行えなかった場合はリセット処理自体を中断し、`error:encryption_failed` といったセンチネルだけが保存されるため、シークレットそのものは残らない。
  - 暗号鍵は環境変数 `MFA_RESET_LOG_ENCRYPTION_KEY` から取得し、未設定の場合は開発用途として `SESSION_SECRET` から派生させたキーを使用する。
  - `readResetLogPayload` が暗号化済みと平文 JSON の両方を復号できるため、既存ログを一括で再暗号化する作業は不要。
- リセット取り消し時（`/platform/tenant-admins/:userId/mfa/rollback`）は、復号したスナップショットを `restoreMfaMethod` / `restoreRecoveryCodes` に渡して復元する。復元後は必ず本人に再設定を促し、ログへ理由を残す。

## TODO / 今後の課題
- `tenant_admin_mfa_reset_logs` を含む MFA 関連テーブルでは `created_at`・`rolled_back_at` が `string` 型のままなので、TIMESTAMPTZ へ移行するマイグレーションを追加する（`docs/db-migration.md` の方針と整合させる）。
- プラットフォーム UI (`views/platform_tenants.ejs`) の確認ダイアログは HTML エスケープ済みのため追加対応不要だが、将来的に属性へ変数を埋め込む場合は `data-*="<%= _.escape(value) %>"` など属性コンテキストのエスケープを徹底する。

## 運用メモ
- 本番では `MFA_RESET_LOG_ENCRYPTION_KEY` を **Secrets Manager** に 32 バイト以上のランダム値（hex もしくは base64）で格納し、ローテーションした際はプロセス再起動を行う。
- 旧ログに平文が残っている場合は、必要に応じてログを削除するか、暗号化済みの状態で作り直す。`readResetLogPayload` が自動判別するため緊急対応は不要。
- リセットやロールバックを実施したら、必ずチケット番号・本人確認方法を `reason` / `rollback_reason` に残して監査証跡を維持する。
