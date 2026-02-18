# Authentication Vulnerabilities: Username Enumeration, 2FA Bypass, and Password Reset Exploitation

Ayaan Mohammed

Tools: Burp Suite (Proxy, Intruder, Repeater) | Platform: PortSwigger Web Security Academy

---

## Why Authentication Matters

Authentication is the front door of every web application. If it's broken, nothing behind it matters. Access controls, encryption, monitoring, all of it becomes irrelevant the moment an attacker can log in as someone else.

What makes authentication vulnerabilities dangerous is that they rarely look dramatic. There's no SQL payload, no shell popping. It's a verbose error message that leaks whether a username exists. It's a 2FA check that doesn't actually enforce verification. It's a password reset token that gets compared to itself instead of being validated against the server. These are logic flaws, and they're the kind of thing automated scanners miss entirely.

This writeup covers four PortSwigger Web Security Academy labs in the authentication module. Each one targets a different failure in how applications verify identity, and each one maps directly to vulnerability classes that appear in real-world assessments.

---

## Lab 1: Username Enumeration via Different Responses

**Difficulty:** Apprentice
**Vulnerability:** Verbose error messages enabling username enumeration
**OWASP Reference:** A07:2021 Identification and Authentication Failures

### The Problem

The application returns different error messages depending on whether a username is valid or invalid. When you submit an invalid username, it responds with "Invalid username." When you submit a valid username with a wrong password, it responds with "Incorrect password." That difference is all an attacker needs to enumerate every valid account in the system.

### How I Approached It

I submitted a random username and password to the login form, then intercepted the POST request to `/login` in Burp Suite's Proxy. The request body was straightforward: `username=test&password=test`.

I sent this request to Intruder, set the username parameter as the payload position, and loaded the candidate username wordlist. Using the Sniper attack type, I fired off the list and watched the response lengths.

Most responses came back at the same length with "Invalid username." One response was slightly longer. When I checked that response, it said "Incorrect password" instead. That confirmed the username was valid.

From there I reset Intruder with the confirmed username hardcoded and set the password parameter as the new payload position. Loaded the candidate password list and started the attack. Every response came back with a 200 status code except one, which returned a 302 redirect. That was the valid password.

Logged in, accessed the account page, lab solved.

### Why This Matters

Two vulnerabilities are at play here. First, the verbose error message. An application should never reveal whether a username exists separately from whether the password is wrong. The correct response for any failed login attempt is a single generic message like "Invalid username or password" regardless of which part was wrong.

Second, there's no brute force protection. The application accepted 100+ rapid login attempts from the same IP without any rate limiting, account lockout, or CAPTCHA. In a real environment, an attacker could enumerate the full user database and then brute force every account with no resistance.

### Remediation

Use a single generic error message for all failed login attempts. Implement rate limiting and account lockout after a defined number of failed attempts. Consider adding CAPTCHA after multiple failures from the same source.

---

## Lab 2: Username Enumeration via Subtly Different Responses

**Difficulty:** Practitioner
**Vulnerability:** Subtle response variation enabling username enumeration
**OWASP Reference:** A07:2021 Identification and Authentication Failures

### The Problem

This is the same vulnerability class as Lab 1, but harder to detect. The application appears to return the same error message for all failed login attempts: "Invalid username or password." At first glance, it looks like the developers did the right thing. But the difference is hidden in the details.

### How I Approached It

I followed the same methodology as Lab 1. Intercepted the login POST request, sent it to Intruder, set the username as the payload position, and loaded the candidate list.

This time I couldn't rely on an obvious difference in the error message text. So I used Burp's Grep Extract feature in the Intruder settings to pull out the exact error message content from each response. When the attack finished, I added a column showing the extracted error message and sorted by it.

Almost every response contained "Invalid username or password." with a period at the end. One response contained "Invalid username or password " with a trailing space instead of a period. That single character difference revealed the valid username.

From there, the password enumeration step was identical to Lab 1. Set the confirmed username, brute force the password field, look for the 302 redirect.

### Why This Matters

This lab demonstrates why automated vulnerability scanners often miss authentication flaws. The difference between a period and a trailing space is invisible to most tools and most testers who aren't looking carefully. It's the kind of finding that comes from paying attention to response patterns during manual testing, not from running a scan and reading the output.

In a real engagement, this kind of subtle inconsistency might exist in error messages, response headers, timing differences, or content length variations. The methodology is the same: compare responses systematically and look for any deviation.

### Remediation

Same as Lab 1, but with an additional emphasis on ensuring error messages are generated from a single code path. When different branches of login logic produce separate error messages, even minor formatting differences can leak information. Use a centralized error response function that returns the exact same string regardless of failure reason.

---

## Lab 3: 2FA Simple Bypass

**Difficulty:** Apprentice
**Vulnerability:** Two-factor authentication not enforced at the application level
**OWASP Reference:** A07:2021 Identification and Authentication Failures

### The Problem

The application implements two-factor authentication by redirecting users to a `/login2` page after they enter valid credentials. That page prompts for a four-digit verification code sent via email. The vulnerability is that the application doesn't actually enforce this step. If you skip the 2FA page entirely and navigate directly to the authenticated area, the application treats you as fully logged in.

### How I Approached It

First I logged in with my own test account to understand the normal 2FA flow. After entering the username and password, the application made a GET request to `/login2` and prompted for a verification code. I retrieved the code from the email client, submitted it, and was redirected to `/my-account`.

Then I logged out and logged in with the victim's credentials (which were provided, simulating a credential dump scenario). When the application redirected me to the `/login2` 2FA prompt, I didn't enter a code. Instead, I turned on Burp's Intercept, caught the request, and dropped it. Then I manually navigated to `/my-account` in the browser.

The application loaded the victim's account page without ever verifying the second factor. Lab solved.

### Why This Matters

This is a fundamental implementation flaw. The developers built a 2FA system but only enforced it at the UI level, not at the server level. The application set the session as authenticated after the first factor (password) and relied on the client-side redirect to enforce the second factor. An attacker who understands HTTP can simply skip that redirect.

This is relevant beyond just 2FA. Any time an application relies on client-side flow control to enforce security checks, an attacker who intercepts traffic with a proxy like Burp can bypass it. Authentication, authorization, payment validation: the server must enforce every check independently.

### Remediation

The session should not be fully authenticated until both factors are verified on the server side. After the first factor succeeds, set a temporary session state that only grants access to the 2FA verification endpoint. Full session privileges should only be granted after the second factor is confirmed. Additionally, enforce server-side checks on every protected endpoint to verify the session has completed all required authentication steps.

---

## Lab 4: Password Reset Broken Logic

**Difficulty:** Apprentice
**Vulnerability:** Password reset token not validated, allowing arbitrary account takeover
**OWASP Reference:** A07:2021 Identification and Authentication Failures

### The Problem

The application's password reset functionality sends a reset link containing a temporary token. When the user submits a new password, the application includes the token and the username in the POST request. The vulnerability is that the application only checks whether the two token parameters in the request match each other. It doesn't validate whether the token is actually legitimate or tied to the account requesting the reset.

### How I Approached It

I started by testing the password reset flow on my own account. Clicked "Forgot your password," entered my username, received the reset email, and clicked the link. The link contained a `temp-forgot-password-token` parameter in the URL.

When I submitted a new password, I intercepted the POST request in Burp and sent it to Repeater. The request contained four parameters: the token in the URL, the token in the body, the username, and the new password (twice for confirmation).

I tested what would happen if I removed the token values entirely. Set both token parameters to an arbitrary value like "x" (matching each other but not a real token), changed the username to the victim's username, set a new password, and sent the request.

The application returned a 302 redirect. It accepted the password change. I logged in as the victim with the new password and accessed the account page. Lab solved.

### Why This Matters

The application compared the token to itself instead of validating it against a server-side record. This means any user who understands the reset request structure can reset any account's password without ever receiving a legitimate reset email.

This is a common implementation error. Developers build the token generation and email delivery correctly but fail to validate the token on the server when the new password is submitted. The fix isn't just about adding validation. It's about understanding that every parameter in a client request can be manipulated, and the server must independently verify every security-critical value.

During the authorized assessment I conducted on a nonprofit's donor platform, I found a related issue: sessions that persisted after password change. That meant even after a user changed their password, an attacker's existing session remained valid. The password reset lab and that real-world finding share the same root cause: the application trusts client-side state that it should be verifying server-side.

### Remediation

Validate the password reset token against the server-side record. Confirm the token has not expired, has not been used before, and is linked to the specific user account requesting the reset. Invalidate the token immediately after a successful password change. Invalidate all existing sessions for the account when the password is reset.

---

## Connecting the Labs

These four labs cover different attack vectors but they share a common theme: the application trusts something it shouldn't.

In the enumeration labs, the application trusts that error message differences are harmless. In the 2FA bypass, the application trusts that the client will follow the intended flow. In the password reset lab, the application trusts that the token in the request is the one it issued.

Every one of these vulnerabilities is invisible to a standard vulnerability scanner. They require a tester who understands application logic, not just someone who runs a tool. That's the difference between a vulnerability assessment and a penetration test, and it's the reason manual testing catches what automation misses.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | Proxy for traffic interception, Intruder for brute force enumeration, Repeater for manual request manipulation |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free hands-on labs for web application security |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Industry standard classification of web application security risks |

---

## About Me

Cybersecurity professional based in Toronto. MS in Information Systems Security Management from Northeastern University. My experience includes SOC operations, penetration testing, and web application security assessments across multiple sectors. Active participant in the OWASP community, building offensive security skills through PortSwigger Web Security Academy and HackTheBox.

[LinkedIn](https://www.linkedin.com/in/ayaan-m-2643122a0/)

---

*This writeup documents labs completed on PortSwigger's Web Security Academy, a deliberately vulnerable training platform. No production systems were tested.*
