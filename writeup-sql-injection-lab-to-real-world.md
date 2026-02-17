# From Real World to Lab: How a Nonprofit Security Assessment Taught Me the True Impact of Web Vulnerabilities

**Author:** Ayaan Mohammed  
**Date:** February 2026  
**Tools Used:** Burp Suite, Nmap, Nikto, OWASP ZAP  
**Platform:** PortSwigger Web Security Academy  

---

## Introduction

There is a moment during every security assessment where a finding stops being academic and starts being real. For me, that moment came while running Burp Suite against a children's charity's donor platform and realizing that a session token sitting in a URL meant an attacker could hijack a donor's payment session.

That single finding changed how I think about web application security. It was not about the technical complexity. It was about the 1.5 million active donors whose trust depended on that application being secure.

This writeup walks through that experience. It starts with the real world, because that is where the stakes are. Then it connects back to PortSwigger Web Security Academy, where I have been building the foundational skills that made those findings possible. The goal is simple: show how lab practice translates into real impact, and why answering "so what" matters more than just finding the vulnerability.

---

## Part 1: The Real World Assessment

### How It Started

While working as a Security Project Assistant at a Canadian nonprofit organization, I was part of a small team conducting a security assessment during a website migration project. This organization serves a vulnerable population and manages a donor platform with over 1.5 million active supporters. Their systems process financial transactions and store personally identifiable information, making them subject to PCI DSS compliance requirements.

The project started as a website migration from WordPress to a new platform. Our team was responsible for evaluating the existing web application for security gaps before the transition. What we found went well beyond what we expected going in.

**Important note:** This assessment was conducted with explicit authorization from the organization's leadership. All findings were reported through proper channels. No data was exfiltrated or accessed beyond the scope of the assessment.

### Setting Up the Assessment

We used Burp Suite to perform a light scan of the organization's public facing website and its secure donor services subdomain. On top of that, we conducted manual testing of the authentication and session management features, DNS reconnaissance to map the infrastructure, and Nikto scans for server level misconfigurations.

The approach was methodical. Start broad with automated scanning, then go deeper on anything that looks interesting. That "go deeper" part is where the real findings came from.

### What We Found

#### The Session Token in the URL

This was the finding that changed everything for me.

The donor facing payment portal embedded a session identifier (jsessionid) directly in the URL of the donation page. To someone who is not in security, that might sound harmless. But here is what it actually means.

That session token shows up in browser history. It gets logged on the web server. It gets sent to third party services through the HTTP Referer header every time the page loads an external resource. A donor could bookmark the page or share the link without realizing their active session is attached to it.

If an attacker obtains that session token, they can hijack the donor's session. That means access to the donor's profile, payment information, and transaction history. For an organization processing charitable donations, this is a direct PCI DSS compliance risk.

**Remediation:** Transmit session tokens exclusively through HTTP cookies with the Secure and HttpOnly flags set, not in URLs.

#### Sessions That Never Die

During manual testing, we discovered something that concerned us even more. Changing a user's password on the donor profile page did not invalidate existing sessions.

We verified this step by step:

1. We logged into the donor portal on two separate browsers at the same time.
2. We changed the password on one browser.
3. We checked the other browser and confirmed the session was still fully active, including the ability to modify profile information.

Think about what this means in practice. A user suspects their account has been compromised. They change their password, expecting that will lock the attacker out. But it does not. The attacker's session remains valid. The security purpose of a password change is completely undermined.

Combined with the session token exposure in URLs, this creates a scenario where an attacker could maintain persistent access to donor accounts even after the victim takes protective action.

**Remediation:** Implement session invalidation upon password change. All active sessions should be terminated, requiring re authentication with the new credentials. Additionally, implement two factor authentication for sensitive account actions.

#### No HSTS Protection

The application failed the HTTP Strict Transport Security test. Without HSTS headers, the site does not instruct browsers to enforce HTTPS only connections. This leaves users vulnerable to downgrade attacks and man in the middle interception.

Picture a donor sitting in a coffee shop, connected to public Wi Fi, making a donation. Without HSTS, an attacker on the same network could intercept the traffic between the donor and the application. Login credentials, session tokens, personal information, all potentially visible.

**Remediation:** Configure the web server to include the Strict Transport Security header with a reasonable max age directive and the includeSubDomains flag.

#### Cookies Without the Secure Flag

Several cookies were set without the Secure flag, meaning they could be transmitted over unencrypted HTTP connections. If a user accidentally accesses any HTTP page, session cookies could be intercepted and used for session hijacking.

**Remediation:** Set the Secure, HttpOnly, and SameSite attributes on all cookies, particularly those related to session management and authentication.

#### Infrastructure Exposure

DNS reconnaissance revealed that the secure donor services subdomain resolved to an IP address owned by a third party donor management platform. Unlike the main domain, which was protected behind Cloudflare's CDN, this subdomain's server IP was directly exposed.

Direct IP exposure allows attackers to bypass CDN level protections like DDoS mitigation and WAF rules and target the underlying server directly. This is particularly concerning for a subdomain that processes financial transactions.

**Remediation:** Route the subdomain through the CDN proxy service to mask the origin server IP. Ensure the origin server only accepts connections from the CDN's IP ranges.

#### Additional Findings

Beyond the critical issues, we identified several lower priority items that still warranted attention.

WordPress source code paths (wp content, wp admin, wp includes) were visible in the page source, giving attackers structural information for targeted attacks. The WordPress cron handler was publicly accessible, creating a potential denial of service vector. Client side scripts contained DOM based open redirection vulnerabilities that could be leveraged for phishing. Missing X Frame Options headers allowed the application to be embedded in iframes on malicious sites. Multiple sitemap backup files (.bak, .old) were publicly accessible.

### Presenting the Findings

Here is where I learned something that no lab teaches you.

We compiled every finding into a prioritized remediation table. High priority items like session management, HSTS, and cookie security at the top. Informational items at the bottom. Each finding included the vulnerability, its business impact, and a clear recommended fix.

When we presented to the organization's leadership, the technical details were not what moved them. It was the "so what." When we explained that an attacker could hijack a donor's payment session and potentially access PCI cardholder data for their 1.5 million active supporters, the room understood. That is a trust issue. That is a funding issue. That is an existential risk for a charity that depends on donor confidence.

The critical session management issues were flagged for immediate attention. The migration team incorporated our findings into the architecture of the new platform.

---

## Part 2: Building the Foundation in the Lab

### Why PortSwigger Web Security Academy

After the nonprofit assessment, I wanted to go deeper into the mechanics of web application vulnerabilities. I had used Burp Suite to find issues on a live system, but I wanted to understand the attack surface at a more granular level. That is what brought me to PortSwigger's Web Security Academy.

The Academy is free, it is built by the people who made Burp Suite, and it covers the full spectrum of web vulnerabilities with hands on labs. I started with SQL injection and authentication vulnerabilities because those are the most common attack vectors I have encountered.

### SQL Injection: Retrieving Hidden Data

The first lab I completed was "SQL Injection Vulnerability in WHERE Clause Allowing Retrieval of Hidden Data." Here is how I approached it.

**The Scenario:** A shopping application uses a product category filter. When you select a category like "Gifts," the application builds a SQL query:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The `released = 1` condition hides unreleased products from users. The objective is to bypass this filter and force the application to display hidden products.

**What I Noticed:** The category parameter is passed through the URL as a query string. When I intercepted the request with Burp Suite's Proxy, I could see the value being placed directly into the WHERE clause with no visible encoding or parameterization. User input going straight into a SQL query is always a red flag.

**My Approach:** I started with the classic detection technique. Append a single quote to the category value and see what happens. If the application breaks or responds differently, the input is being interpreted as SQL.

Then I modified the category parameter to:

```
'+OR+1=1--
```

This does two things. `OR 1=1` creates a condition that is always true, so the query returns all rows regardless of category. The `--` comments out the rest of the query, removing the `AND released = 1` restriction.

The resulting query becomes:

```sql
SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
```

**The Result:** The application returned all products, including unreleased items that should have been hidden. Lab solved.

### SQL Injection: Bypassing Authentication

The second lab took the same concept further. Instead of retrieving hidden data, the goal was to log in as the administrator without knowing the password.

By modifying the username parameter to `administrator'--`, the application executed:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

The password check is commented out entirely. The application authenticates based on the username alone.

This is where I saw the direct connection to my real world experience. The nonprofit's donor portal had session management weaknesses that could lead to unauthorized account access. The SQL injection lab demonstrated how an attacker could bypass authentication entirely if input validation is missing. Different vulnerability, same outcome: unauthorized access to user accounts.

### Authentication Vulnerabilities

I have also been working through PortSwigger's authentication module, covering how password based login systems can be exploited through brute force attacks, credential stuffing, and flawed session management.

The material on session handling connected directly to what I found at the nonprofit. The lab explains how session tokens should be managed, what happens when they are exposed, and why proper invalidation matters. Reading that after having already discovered those exact issues in a live environment made the concepts click in a way that purely academic learning never could.

---

## Part 3: Lessons Learned

**1. Real findings come from manual testing.** Burp Scanner and Nikto identified surface level issues. But the most impactful finding, sessions persisting after password change, came from manual testing and understanding the application's logic. Tools find vulnerabilities. Testers prove impact.

**2. Always answer the "so what."** A session token in a URL means nothing to a nontechnical stakeholder. "An attacker could hijack a donor's payment session and access PCI cardholder data" means everything. The ability to translate technical severity into business risk is what makes a finding actionable.

**3. Lab practice builds real world instincts.** PortSwigger Academy taught me to look for injection points and think about how data flows through an application. That same mindset, where does user input go and what can I make it do, is exactly what led to the most significant findings in the live assessment.

**4. Client communication matters as much as technical skill.** Presenting findings to a nonprofit's leadership requires translating technical severity into business risk. A prioritized remediation table with clear impact statements was more valuable to them than raw scan output.

**5. Protect your clients.** Every piece of identifying information has been removed from this writeup. No organization names, no URLs, no infrastructure details. That is not just good practice. It is the foundation of the trust that makes security work possible.

---

## Tools and Resources

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | Web vulnerability scanning, request interception, manual testing |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free hands on labs for web application security |
| [Nmap](https://nmap.org/) | Network reconnaissance and service enumeration |
| [Nikto](https://github.com/sullo/nikto) | Web server vulnerability scanning |
| [OWASP ZAP](https://www.zaproxy.org/) | Open source web application security testing |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Industry standard for web application security risks |

---

## About Me

I am a cybersecurity professional based in Toronto with a Master of Science in Information Systems Security Management from Northeastern University. My experience spans SOC operations, penetration testing, and web application security assessments for organizations across multiple sectors. I am an active participant in the OWASP community and continue to build my offensive security skills through platforms like PortSwigger Web Security Academy and HackTheBox.

Connect with me on [LinkedIn](https://linkedin.com/) or check out more of my work on [GitHub](https://github.com/).

---

*This writeup reflects authorized security assessment work. All client identifying information has been removed to protect organizational privacy. No sensitive data was accessed or exfiltrated during the assessment.*
