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





# app.js
- Potential race condition in concurrent MFA verification attempts.
- Same race condition issue applies to email OTP failure tracking.
- Resend interval is appropriate; flag OTP lifetime for review.
    - The 60-second resend interval aligns with industry standards—enforce a 30-60 second cooldown plus rate limiting per OWASP, Auth0, and NIST guidance. However, limit OTP lifetime to a short window (e.g., ≤5 minutes), while your EMAIL_OTP_TTL_MS is set to 10 minutes. Additionally, ensure at most ~3-5 resends per user/address per 30-60 minutes with exponential back‑off and temporary block on excessive requests are implemented to prevent abuse. Verify the full rate-limiting policy is enforced beyond the resend interval timing.

# admin_sessions.ejs
- Missing delete confirmation handler.
    - The delete buttons specify data-confirm-message, but there's no JavaScript code that reads this attribute and displays a confirmation dialog. The client script (lines 201-255) only handles the add-form confirmation. This means delete actions will execute immediately without user confirmation, which is a data safety issue.
- Table inputs lack explicit labels for accessibility.
    - The datetime inputs in the table rely solely on column headers (<th>) for labeling. Screen readers may not properly associate these headers with the inputs in each cell, making the form difficult to navigate for users with disabilities.
- Dialog lacks proper ARIA attributes for accessibility.

# login_mfa.ejs
- Similar accessibility concern for email lock state.
    - As with the TOTP lock message, this lock notification should be programmatically associated with the disabled form controls using aria-describedby.
- Static countdown timer requires page refresh.
    - The resendWaitSeconds countdown (line 82) displays the initial value but won't update dynamically without client-side JavaScript. Users must manually refresh the page to see the countdown progress or know when they can resend.Consider one of these solutions:Add a client-side JavaScript countdown timer,Add a note informing users they need to refresh the page,Implement server-sent events or polling to update the state
- Associate error messages with form controls for accessibility.
    - The lock error message is displayed but not programmatically associated with the disabled form field. Screen reader users may not understand why the input is disabled.

# sqlRepository.js
- Potential race condition in non-RETURNING database clients.
    - For MySQL and SQLite (lines 160-164), the insert and subsequent fetch are not atomic. If another operation modifies or deletes the row between the insert (line 161) and fetch (line 163), the method could return stale or null data.This is unlikely in typical usage but could occur under high concurrency or if there are cascading triggers.
- MFA-related tables are missing from deleteAllData.
    - Lines 854-860 delete from specific tables but omit MFA-related tables that are referenced in methods later in the file:user_mfa_methods (line 900, 906, 912, etc.),user_mfa_recovery_codes (line 997, 1002, etc.),user_mfa_trusted_devices (line 1077, 1092, etc.),tenant_admin_mfa_reset_logs (line 1124, 1133, etc.)
    - These should be included in the deletion order before users to respect foreign key constraints.

# admin_dashboard.ejs
- Potential runtime error if tenantSettings is undefined.
    - The conditional tenantSettings && tenantSettings.requireEmailVerification will throw a ReferenceError if tenantSettings is not defined in the template context at all (as opposed to being null or undefined). Ensure the server-side route handler always passes tenantSettings to the template, even if it's null or an empty object.
- Ensure queryString is URL-encoded on the server side before rendering in href attribute.
    - Template variables in href values can still accept javascript: URIs without being prevented by HTML escaping. While EJS's <%= %> provides HTML entity escaping, it does not handle URL encoding. Untrusted data put into URL query strings must be URL encoded to prevent injection attacks. The queryString variable should be URL-encoded server-side before being passed to the template to prevent query string injection and protocol attacks.

# admin_payrolls.ejs
- Remove redundant CSRF token from URL query parameter.
    - The CSRF token is included both in the URL query parameter (line 50) and as a hidden form field (line 53). This is redundant and follows an insecure pattern—CSRF tokens should not be exposed in URLs as they can leak through referrer headers, browser history, and server logs.
- Potential XSS vulnerability with unescaped JSON output.
    - Using <%- (unescaped output) with JSON.stringify can introduce XSS vulnerabilities if sentTodayEmployeeIds contains user-controlled data or hasn't been properly sanitized server-side.

# register.ejs
- Missing verification code input field for functionality described in the note.
    - The note states that some tenants require entering a 6-digit verification code sent to the email address before registration. However, there is no corresponding input field in the form (lines 32-57) to capture this verification code. Users who receive such a code will have no way to enter it.

# role_codes.ejs
- Add a maximum value constraint for usage limit input.
    - The number input for maxUses has a minimum value of 1 but no maximum constraint. Without a max attribute, users could input unrealistically large values that might cause database or application issues.

# 20251119160000_add_email_otp_requests.js
- Use proper timestamp types instead of strings.
    - Storing timestamps as strings prevents:Proper date comparisons (e.g., WHERE expires_at < NOW()),Use of database date functions,Correct sorting and indexing by date
    - For OTP expiration logic, this will cause issues when checking if codes have expired.

# otpService.js
- Modulo bias creates non-uniform OTP distribution.
    - The current implementation using byte % 10 introduces modulo bias. Since 256 doesn't divide evenly by 10, digits 0-5 each appear 26 times in the range [0, 255], while digits 6-9 appear only 25 times. This ~4% bias reduces the effective entropy of the OTP and could be exploited in attacks.







# app.js
- In-memory rate limiter will not persist across restarts or scale horizontally.
    - The emailOtpRateLimiter Map is stored in application memory, which means:Rate limit state is lost when the server restarts,In multi-instance deployments (load-balanced), each instance maintains separate state,Users could potentially bypass rate limits by hitting different instances.
    - Consider using a shared persistent store (Redis, database) for rate limiting state to ensure consistent enforcement across restarts and instances.
- Trusted device cookie cleared after email OTP login but preserved after TOTP.
    - Line 1964 clears the trusted device cookie after successful email OTP verification, but lines 1997-2004 conditionally set or clear it for TOTP based on user preference. This inconsistency means:Email OTP users cannot benefit from device trust,Users must always complete email OTP even on trusted devices
    - Consider allowing device trust for email OTP by moving the clearTrustedDeviceCookie call or making it conditional on a user preference similar to TOTP.
- OTP codes logged in non-production environments could leak in logs.
    - The OTP code is logged to console in development/test environments. If these logs are accessible (e.g., CloudWatch, shared development servers), this could allow unauthorized access.
    - Consider:Using a more secure distribution method even in development,Ensuring development logs are properly secured,Adding prominent warnings about the security implications
- Password hash stored in email OTP challenge metadata.
    - The hashed password is stored in the email OTP challenge metadata (line 2149). While the hash itself is already protected, this creates an additional location where sensitive authentication data is stored. If the email_otp_requests table is compromised, attackers could attempt to crack these hashes offline.
    - Consider:Storing only non-sensitive registration data in metadata and requiring password re-entry after verification,Adding explicit database-level encryption for the metadata column,Documenting this security trade-off in the code
- Potential race condition in OTP refresh when rate limit is enforced.
    - The refreshEmailOtpChallenge function deletes the old challenge (line 1085) then calls issueEmailOtpChallenge (line 1086). If the user has hit the rate limit, the new challenge creation will fail but the old challenge has already been deleted, leaving the user with no valid OTP.

# 20251119160000_add_email_otp_requests.js
- Add .notNullable() constraint to user_id.
    - Every OTP request must belong to a user. Without this constraint:Orphaned records with no user association could exist.,The unique constraint on (user_id, purpose) at line 52 will behave unexpectedly with NULL values (different databases handle NULL in unique constraints differently).
- Add length constraint to target_email.
    - The target_email field lacks a length constraint, which could lead to database performance issues. Email addresses are typically limited to 254-320 characters per RFC standards.
- Add default values for created_at and updated_at.
    - These timestamp fields are marked as notNullable() but lack default values, which will cause insertion errors if not explicitly provided.

# sqlRepository.js
- Inconsistent null handling for profile fields.
    - Lines 296-301 use typeof === 'string' for firstName and lastName, preventing them from being set to null, while line 302 uses !== undefined for phoneNumber, which allows null. This inconsistency may be intentional if names must be non-nullable, but it's worth verifying.
    - Also note that this method doesn't return the updated user, unlike updateTenantRegistrationSettings, which might be intentional but creates API inconsistency.

# mfaService.js
- Breaking change: Default MFA issuer name has changed.
    - The default issuer name changed from 'TimeRecordSystem' to 'Attendly'. This issuer name appears in users' authenticator apps and is part of the TOTP key URI. Changing it has the following impacts:Existing users who have already enrolled in MFA will see 'TimeRecordSystem' in their authenticator apps,New enrollments or re-enrollments will show 'Attendly' instead,Users may end up with duplicate entries in their authenticator apps if they enroll again,Authenticator apps treat different issuer names as separate accounts, potentially causing confusion
    - Consider of these approaches:Option 1 (recommended): Preserve backward compatibility
    -function getMfaIssuer(defaultName = 'Attendly') {
    +function getMfaIssuer(defaultName = 'TimeRecordSystem') {
    return process.env.MFA_ISSUER || defaultName;
    }

# admin_sessions.ejs
- Inconsistent terminology in the dialogue text.
    - While the dialogue uses the term “労務記録,” other parts of the page consistently use “勤務記録” in the title (line 6), section headings (lines 39, 65, 98), and data attributes (line 154). This inconsistency may confuse users.The term should be unified to “勤務記録”.


-fixed-


-needs fix-