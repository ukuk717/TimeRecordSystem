# TimeRecordSystem Agent Guide

- All responses to users must be in Japanese. If the output is in English, it must be translated before output.
- Please ensure that Japanese text is entered strictly in UTF-8 format. Mixing with other encodings such as Shift-JIS is not permitted.
## Critical Test Warning
- Do not run `npm test`, `npm run test`, `npx jest`, or `yarn test`.
- Running the Jest suite currently hangs indefinitely and freezes the session (observed on 2025-10-21). Treat tests as unavailable until this note is removed.
- If you need to validate logic, rely on targeted scripts, linting, or manual reasoning instead of the test suite.

## Alternative Validation
- Favor lightweight checks (e.g., invoking individual modules with `node`) that avoid loading Jest.
- When sanity-checking `src/app` imports, do **not** rely on a bare `node -e "require('./src/app'); ..."`; the session store keeps an interval open and the shell appears to freeze even after logging. Instead run `NODE_ENV=test node -e "require('./src/app'); setImmediate(() => process.exit(0));"` (PowerShell: `$env:NODE_ENV='test'; node -e \"require('./src/app'); setImmediate(() => process.exit(0));\"`).
- Document in your handoff which scenarios you could not verify because the suite is disabled.

## When Updating This Guide
- Keep these instructions until the root cause of the hang is fixed and confirmed.
- If you find a safe workaround for running tests, update this file with clear steps before removing the warning above.

