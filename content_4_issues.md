## 問題の修正

# 必ずAGENTS.mdに従い、実装を行うこと。

- プラットフォーム管理者のアカウント上で、"登録済みテナント"の表示に異常がある問題
    - テナントUID/名称/連絡先メールが表示されない問題
    - 名称/連絡先メールは未設定となっている。
    - 登録日時は正常。

- 従業員アカウント/テナント管理者アカウント共に"印刷/ダウンロード"両方が機能しない問題
    - 下記のようなエラーが発生している。
    ```
    #従業員アカウント
    TypeError [ERR_INVALID_CHAR]: Invalid character in header content ["Content-Disposition"]
    at ServerResponse.setHeader (node:_http_outgoing:703:3)
    at applyContentDisposition (Z:\grandseed\TimeRecordSystem\TimeRecordSystem\src\app.js:282:7)
    at Z:\grandseed\TimeRecordSystem\TimeRecordSystem\src\app.js:1044:7
    ```
    ```
    #テナント管理者アカウント
    TypeError [ERR_INVALID_CHAR]: Invalid character in header content ["Content-Disposition"]
    at ServerResponse.setHeader (node:_http_outgoing:703:3)
    at applyContentDisposition (Z:\grandseed\TimeRecordSystem\TimeRecordSystem\src\app.js:282:7)
    at Z:\grandseed\TimeRecordSystem\TimeRecordSystem\src\app.js:1301:7
    ```