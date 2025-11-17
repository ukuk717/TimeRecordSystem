-fixed-

- platform_tenants.ejs
    - Add CSRF protection to the tenant registration form.
    - Add CSRF protection to the logout form.
    - Escape generated tenant data to prevent XSS.
    - Add error handling for invalid date values.
- role_codes.ejs
    - Add CSRF protection to all forms.
    - Validate dates before formatting.
    - Use explicit null check instead of || operator.
    - Validate code.status server-side to prevent XSS.
- app.js
    - Critical: Remove default session secret.
    - Ensure password reset links are not logged~~ in production.~~
- userService.js
    - Fix modulo bias in random character selection.
    - Ensure generated password meets validation requirements.
- log.md
    - Remove hardcoded default credentials from documentation and implementation.
    - Clarify sensitive data handling in logging and backup procedures.
- db.js
    - Critical: Table creation order violates foreign key constraints.
- password_reset_requests.ejs
    - Add CSRF protection to the form.
- register.ejs
    - Clarify roleCode character set requirements.

-fixed-
- app.js
    - Ephemeral session secret will invalidate sessions on restart.
    - Add 'secure' flag to session cookies in production.
    - ~~Fix modulo bias in random code generation.~~
    - Validate host header to prevent host header injection.
    - Replace deprecated 'csurf' package with actively maintained alternative.
    - Move CSRF protection after static file middleware.
- db.js
    - ~~Consider adding constraints to prevent orphaned users and duplicate usernames.~~
    - ~~Email normalization inconsistency creates a risk.~~
    - ~~Fix garbled error message.~~
    - ~~Remove the UTF-8 BOM character.~~

-needs fix-

# 20251117153000_convert_mfa_timestamps.js
Generic migration path may lose data or produce inconsistent results.

The generic migration has several critical issues:

Data loss in DOWN migration (lines 148-154): When reverting from timestamptz to string, Knex's .string() and .alter() don't support custom conversion expressions. The database will use its default casting, which may not produce ISO 8601 formatted strings as the PostgreSQL path does (line 89). This means the data format won't be consistent with the original format.

Ambiguous timezone handling (lines 136-146): When reverting from timestamptz to timestamp, tbl.timestamp(column.name) doesn't explicitly set useTz: false. Depending on the database and Knex configuration, this might create a timestamp WITH timezone instead of without, failing to properly revert the migration.

No length specification (line 148): tbl.string(column.name) doesn't specify a length, while the PostgreSQL path uses VARCHAR(255). Different databases may use different defaults.

Consider one of these approaches:

Option 1 (Recommended): Restrict this migration to PostgreSQL only, since the generic path cannot reliably handle the complex type conversions:

 exports.up = async (knex) => {
   if (isPostgres(knex)) {
     await runPostgresMigration(knex, 'up');
     return;
   }
-  await runGenericMigration(knex, 'up');
+  throw new Error('This migration only supports PostgreSQL');
 };