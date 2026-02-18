# Access Control Vulnerabilities: Broken Admin Panels, Privilege Escalation, and Forgeable Cookies

Ayaan Mohammed

Tools: Burp Suite (Proxy, Repeater, Intruder) | Platform: PortSwigger Web Security Academy

---

## Why Access Control Matters

Authentication asks "who are you?" Access control asks "what are you allowed to do?" They're different questions, and breaking one doesn't require breaking the other.

An application can have perfect authentication, strong passwords, 2FA, session management done right, and still be completely compromised if access control is missing or implemented on the wrong layer. An admin panel with no authorization check. A user ID in a URL parameter that no one validates. A cookie that says "admin=false" and trusts the client not to change it.

These are the vulnerabilities that lead to full application compromise, and they're consistently in the OWASP Top 10 (A01:2021 Broken Access Control holds the number one position). This writeup covers five PortSwigger Web Security Academy labs that demonstrate different ways access control fails.

---

## Lab 1: Unprotected Admin Functionality

**Difficulty:** Apprentice
**Vulnerability:** Admin panel with no access control enforcement
**OWASP Reference:** A01:2021 Broken Access Control

### The Problem

The application has an admin panel that allows user management including account deletion. The panel exists at a discoverable URL and has no authentication or authorization checks protecting it.

### How I Approached It

The first step was reconnaissance. I checked `/robots.txt`, which disclosed a `Disallow` directive pointing to `/administrator-panel`. Navigating directly to that path loaded the full admin panel without requiring any login or session.

From there I simply clicked delete on the target user account. No credentials needed, no session required. Lab solved.

### Why This Matters

This is the most basic form of broken access control: the developers built admin functionality but never restricted who could access it. In a real environment, an attacker would find this through directory brute forcing, robots.txt disclosure, sitemap files, or JavaScript source code analysis. Once found, the impact is immediate and total.

### Remediation

Implement server-side access control checks on every administrative endpoint. Never rely on obscurity (hiding the URL) as a security measure. Enforce role-based access control that verifies the authenticated user's permissions before processing any request.

---

## Lab 2: Unprotected Admin Functionality with Unpredictable URL

**Difficulty:** Apprentice
**Vulnerability:** Admin panel URL disclosed in client-side JavaScript
**OWASP Reference:** A01:2021 Broken Access Control

### The Problem

The admin panel is located at an unpredictable URL that cannot be brute forced. However, the URL is leaked in the application's front-end JavaScript code.

### How I Approached It

I started with robots.txt but it didn't exist. Next I viewed the page source code on the home page and found JavaScript that contained conditional logic for admin functionality. The script checked whether the current user was an admin, and if true, it rendered a link to the admin panel. The admin panel URL was hardcoded in that JavaScript block.

I copied the URL, navigated to it directly, and gained full access to the admin panel without authentication. Deleted the target user. Lab solved.

### Why This Matters

The developers attempted security through obscurity by using an unpredictable URL. But they included the URL in client-side code that every visitor receives regardless of their role. This is a pattern that appears frequently in real applications: sensitive endpoints referenced in JavaScript bundles, HTML comments, or API documentation that's served to all users.

During the authorized assessment I conducted on a nonprofit's donor platform, I found a similar issue: WordPress source code paths (wp-content, wp-admin, wp-includes) were visible in the page source, giving attackers structural information about the application. The principle is the same: anything in client-side code is visible to everyone.

### Remediation

Never embed sensitive URLs or administrative endpoints in client-side code. Implement server-side access control regardless of whether the URL is predictable. If admin-only JavaScript is needed, serve it conditionally from the server based on the authenticated user's role.

---

## Lab 3: User Role Controlled by Request Parameter

**Difficulty:** Apprentice
**Vulnerability:** Admin access determined by a client-side cookie
**OWASP Reference:** A01:2021 Broken Access Control

### The Problem

The application determines whether a user is an admin by reading a cookie called `Admin` that is set to `false` for regular users. Since cookies are stored client-side, any user can modify this value.

### How I Approached It

I logged in with the provided credentials and intercepted the response in Burp Suite's Proxy. The response set two cookies: a session cookie and an `Admin=false` cookie. I navigated to `/admin` and confirmed it was blocked for regular users.

Then I opened the browser's developer tools, went to the Application tab, found the cookies section, and changed `Admin=false` to `Admin=true`. Reloaded the page and the admin panel appeared. I deleted the target user. Lab solved.

### Why This Matters

This is a fundamental access control mistake: trusting the client to honestly report its own privilege level. Cookies, hidden form fields, URL parameters, and request headers are all under the attacker's control. Any security decision based on a client-supplied value without server-side validation is exploitable.

### Remediation

Never store authorization state in client-side cookies or parameters. Determine user roles from the server-side session store. When processing a request, look up the authenticated user's role from the database, not from anything the client sends.

---

## Lab 4: User ID Controlled by Request Parameter with Unpredictable User IDs

**Difficulty:** Apprentice
**Vulnerability:** Horizontal privilege escalation via leaked GUIDs
**OWASP Reference:** A01:2021 Broken Access Control

### The Problem

The application uses GUIDs (Globally Unique Identifiers) for user accounts, which means the IDs cannot be guessed or brute forced. However, the application leaks user GUIDs in other parts of the application, and the account page does not verify that the requesting user is authorized to view the requested account.

### How I Approached It

I logged in with the provided credentials and noted that the account page URL contained my GUID as the `id` parameter. The GUID was long and random, so brute forcing was not viable.

I went back to the home page and browsed the blog posts. Each post displayed the author's name as a clickable link. When I clicked on a post written by the target user Carlos, the resulting URL contained Carlos's GUID.

I copied that GUID, went back to Burp Repeater, replaced my own ID with Carlos's GUID in the account page request, and sent it. The application returned Carlos's full account page including his API key. Submitted the API key. Lab solved.

### Why This Matters

Using unpredictable identifiers like GUIDs is not access control. It's obscurity. The application correctly made the IDs unguessable, but it leaked them through the blog post author links, and it never verified that the requesting user had permission to view the requested account.

This is horizontal privilege escalation: a regular user accessing another regular user's data. In a real application, GUIDs might be leaked through API responses, URL parameters in shared links, browser history, referrer headers, or error messages. The defense is not making IDs harder to guess. The defense is checking authorization on every request.

### Remediation

Implement authorization checks that verify the authenticated user has permission to access the requested resource. The server should compare the session user's identity against the resource being requested, regardless of whether the resource ID is predictable.

---

## Lab 5: User ID Controlled by Request Parameter with Password Disclosure

**Difficulty:** Apprentice
**Vulnerability:** Horizontal to vertical privilege escalation via password disclosure in HTML source
**OWASP Reference:** A01:2021 Broken Access Control

### The Problem

The application's account page pre-fills the user's existing password in a masked input field. While the password appears hidden in the browser, the actual value is present in the HTML source. Combined with a broken access control vulnerability that allows viewing any user's account page, this exposes the administrator's password.

### How I Approached It

I logged in with the provided credentials and loaded my account page. The page included a password field that appeared masked in the browser. I right-clicked, inspected the element, and found the password value in the HTML input tag's `value` attribute. That confirmed the password disclosure vulnerability.

Next I tested for broken access control. I changed the `id` parameter in the URL from my username to `administrator` and sent the request through Burp Repeater. The application returned the administrator's account page, complete with the pre-filled password visible in the HTML source.

I copied the administrator's password, logged out, logged in as the administrator, accessed the admin panel, and deleted the target user. Lab solved.

### Why This Matters

This lab chains two vulnerabilities together. The first is broken access control: any authenticated user can view any other user's account page by modifying the ID parameter. The second is sensitive data exposure: the password is embedded in the HTML response.

Neither vulnerability alone would be critical. A masked password field without the access control flaw only exposes the user's own password (which they already know). The access control flaw without the password disclosure only shows usernames and email addresses. But together they allow full administrator account takeover.

This is how real-world attacks work. Individual findings combine into attack chains that escalate from low-severity to critical. A penetration tester's job is not just finding individual vulnerabilities but understanding how they interact.

### Remediation

Never include existing passwords in HTML responses, even in masked input fields. For password changes, require the user to enter their current password as a separate validation step rather than pre-filling it. Implement server-side access control that prevents users from accessing other users' account pages.

---

## Connecting the Labs

All five labs target the same OWASP category but exploit different implementation failures. Missing access control on admin endpoints. Sensitive URLs in client-side code. Authorization state stored in modifiable cookies. Broken object-level authorization on user accounts. Sensitive data exposed in HTML source.

The common thread is that access control must be enforced server-side on every request, for every resource, regardless of how the request arrives. Client-side controls (hidden URLs, masked fields, cookie values) are presentation features, not security features. An attacker with a proxy like Burp Suite bypasses all of them in seconds.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | Proxy for traffic interception, Repeater for manual request manipulation, browser developer tools for cookie modification |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free hands-on labs for web application security |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Industry standard classification of web application security risks |

---

## About Me

Cybersecurity professional based in Toronto. MS in Information Systems Security Management from Northeastern University. My experience includes SOC operations, penetration testing, and web application security assessments across multiple sectors. Active participant in the OWASP community, building offensive security skills through PortSwigger Web Security Academy and HackTheBox.

[LinkedIn](https://www.linkedin.com/in/ayaan-m-2643122a0/)

---

*This writeup documents labs completed on PortSwigger's Web Security Academy, a deliberately vulnerable training platform. No production systems were tested.*
