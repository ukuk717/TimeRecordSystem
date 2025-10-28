const fs = require("fs");
const path = "src/app.js";
let text = fs.readFileSync(path, "utf8");
const replacements = new Map([
  ["setFlash(req, 'error', '繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｨ繝代せ繝ｯ繝ｼ繝峨ｒ蜈･蜉帙＠縺ｦ縺上□縺輔＞縲・);", "setFlash(req, 'error', 'メールアドレスとパスワードを入力してください。');"],
  ["setFlash(req, 'error', 'メールアドレスまた�Eパスワードが正しくありません、E);", "setFlash(req, 'error', 'メールアドレスまたはパスワードが正しくありません。');"],
  ["`アカウントがロチE��されてぁE��す、E{remainingMinutes}刁E��に再度お試しください。`", "`アカウントがロックされています。${remainingMinutes}分後に再度お試しください。`"],
  ["`ログインに${LOGIN_FAILURE_LIMIT}回連続で失敗したため、E{LOGIN_LOCK_MINUTES}刁E��ロチE��しました。`", "`ログインに${LOGIN_FAILURE_LIMIT}回連続で失敗したため、${LOGIN_LOCK_MINUTES}分ロックしました。`"],
  ["`メールアドレスまた�Eパスワードが正しくありません。（あと${remaining}回でロチE���E", "`メールアドレスまたはパスワードが正しくありません。（あと${remaining}回でロックされます）`"],
  ["setFlash(req, 'success', '繝ｭ繧ｰ繧､繝ｳ縺励∪縺励◆縲・);", "setFlash(req, 'success', 'ログインしました。');"],
  ["const firstNameResult = validateNameField('吁E, req.body.firstName);", "const firstNameResult = validateNameField('名', req.body.firstName);"],
  ["const lastNameResult = validateNameField('姁E, req.body.lastName);", "const lastNameResult = validateNameField('姓', req.body.lastName);"],
  ["setFlash(req, 'error', 'メールアドレスを�E力してください、E);", "setFlash(req, 'error', 'メールアドレスを入力してください。');"],
  ["setFlash(req, 'error', 'ロールコードを入力してください、E);", "setFlash(req, 'error', 'ロールコードを入力してください。');"],
  ["setFlash(req, 'error', 'ロールコードが無効です、E);", "setFlash(req, 'error', 'ロールコードが無効です。');"],
  ["setFlash(req, 'error', 'こ�Eロールコード�E無効化されてぁE��す、E);", "setFlash(req, 'error', 'このロールコードは無効化されています。');"],
  ["setFlash(req, 'error', 'ロールコード�E有効期限が�EれてぁE��す、E);", "setFlash(req, 'error', 'ロールコードの有効期限が切れています。');"],
  ["setFlash(req, 'error', 'ロールコード�E利用上限に達してぁE��す、E);", "setFlash(req, 'error', 'ロールコードの利用上限に達しています。');"],
  ["setFlash(req, 'error', 'こ�Eメールアドレスは既に登録されてぁE��す、E);", "setFlash(req, 'error', 'このメールアドレスは既に登録されています。');"],
  ["setFlash(req, 'success', '繧｢繧ｫ繧ｦ繝ｳ繝医ｒ菴懈・縺励∪縺励◆縲ゅΟ繧ｰ繧､繝ｳ縺励※縺上□縺輔＞縲・);", "setFlash(req, 'success', 'アカウントを作成しました。ログインしてください。');"],
  ["console.error('[register] 蠕捺･ｭ蜩｡繧｢繧ｫ繧ｦ繝ｳ繝井ｽ懈・縺ｫ螟ｱ謨励＠縺ｾ縺励◆', error);", "console.error('[register] 従業員アカウント作成に失敗しました', error);"],
  ["setFlash(req, 'error', '繧｢繧ｫ繧ｦ繝ｳ繝井ｽ懈・荳ｭ縺ｫ繧ｨ繝ｩ繝ｼ縺檎匱逕溘＠縺ｾ縺励◆縲・);", "setFlash(req, 'error', 'アカウント作成中にエラーが発生しました。');"],
  ["setFlash(req, 'error', '繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ繧貞・蜉帙＠縺ｦ縺上□縺輔＞縲・);", "setFlash(req, 'error', 'メールアドレスを入力してください。');"],
  ["setFlash(req, 'info', '繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・ヨ謇矩・ｒ繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｸ騾∽ｿ｡縺励∪縺励◆縲・);", "setFlash(req, 'info', 'パスワードリセット用のリンクをメールアドレスへ送信しました。（開発環境ではサーバーのログを確認してください）');"],
  ["setFlash(req, 'error', '繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ縺檎┌蜉ｹ縺ｧ縺吶ょ・蠎ｦ謇狗ｶ壹″繧定｡後▲縺ｦ縺上□縺輔＞縲・);", "setFlash(req, 'error', 'リセットリンクが無効です。再度手続きを行ってください。');"],
  ["setFlash(req, 'error', '繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ縺ｮ譛牙柑譛滄剞縺悟・繧後※縺・∪縺吶・);", "setFlash(req, 'error', 'リセットリンクの有効期限が切れています。');"],
  ["setFlash(req, 'error', '繝ｦ繝ｼ繧ｶ繝ｼ縺悟ｭ伜惠縺励∪縺帙ｓ縲・);", "setFlash(req, 'error', 'ユーザーが存在しません。');"],
  ["setFlash(req, 'success', '繝代せ繝ｯ繝ｼ繝峨ｒ蜀崎ｨｭ螳壹＠縺ｾ縺励◆縲ゅΟ繧ｰ繧､繝ｳ縺励※縺上□縺輔＞縲・);", "setFlash(req, 'success', 'パスワードを再設定しました。ログインしてください。');"],
  ["setFlash(req, 'error', '繝ｦ繝ｼ繧ｶ繝ｼ縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縲・);", "setFlash(req, 'error', 'ユーザーが見つかりません。');"],
  ["setFlash(req, 'error', '迴ｾ蝨ｨ縺ｮ繝代せ繝ｯ繝ｼ繝峨′豁｣縺励￥縺ゅｊ縺ｾ縺帙ｓ縲・);", "setFlash(req, 'error', '現在のパスワードが正しくありません。');"],
  ["setFlash(req, 'success', '繝代せ繝ｯ繝ｼ繝峨ｒ螟画峩縺励∪縺励◆縲・);", "setFlash(req, 'success', 'パスワードを変更しました。');"],
]);
for (const [from, to] of replacements) {
  if (!text.includes(from)) {
    throw new Error(`Replacement target not found: ${from}`);
  }
  text = text.replace(from, to);
}
fs.writeFileSync(path, text, "utf8");
