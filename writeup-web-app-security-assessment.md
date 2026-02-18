# Web Application Security Assessment: Session Management and Authentication Vulnerabilities in a Nonprofit Donor Platform

Ayaan Mohammed

*Confidentiality notice: All client identifying information has been removed from this writeup to protect organizational privacy. Specific details including organization name, infrastructure, donor counts, and platform identifiers have been omitted or generalized.*

Tools: Burp Suite, Nmap, Nikto, OWASP ZAP | Lab Platform: PortSwigger Web Security Academy

---

## Background

I was running Burp Suite against a nonprofit's donor platform when I noticed a session token sitting right there in the URL. Not hidden, not protected, just appended to the donation page link. That meant anyone who got that URL could hijack a donor's payment session.

That's when it clicked for me that this stuff has real consequences. It's not about the technical complexity, it's about real people trusting this application with their payment info.

This writeup goes through what I found during that assessment, then connects it back to the PortSwigger labs where I've been sharpening the skills that made those findings possible. The idea is to show how lab work actually translates to real findings and why the "so what" matters more than just pointing out a vulnerability.

---

## Part 1: The Real World Assessment

### How it started

I was working as a Security Project Assistant at a Canadian nonprofit. The organization was going through a website migration from a legacy CMS to a new platform, and our small team was brought in to assess the existing web application for security gaps before the transition.

The organization runs a donor platform that processes financial transactions and stores PII, so PCI DSS compliance was a factor. We were expecting to find some misconfigured headers and maybe some outdated components. What we actually found was a lot worse.

To be clear, this was all done with explicit authorization from the organization's leadership. Everything was reported through proper channels. No data was exfiltrated or accessed beyond scope.

### How we set up

We ran Burp Suite for a light scan on the public facing site and the donor services subdomain. On top of that we did manual testing on authentication and session management, DNS recon to map out the infrastructure, and Nikto scans for server level issues.

Pretty standard approach. Start broad with the automated stuff, then dig into anything that looks off. The manual testing is where the real findings came from.

### Findings overview

Burp returned 1 medium, 5 low, and 78 informational items. But the automated scan missed the worst stuff. The highest impact findings all came from manual testing. Here's what carried the most weight.


### Finding 1: Session token exposed in donation URL

Severity: Medium | Confidence: Firm

This was the big one.

The donor payment portal had a jsessionid embedded directly in the URL of the donation page. Burp caught it during the automated scan on one of the localized donation paths. The token was appended to the payment form link right alongside analytics tracking parameters and a nonce.

If you're not in security that probably sounds harmless. It's not. That session token ends up in browser history, server logs, and gets sent to every third party service through the Referer header whenever the page loads an external resource. A donor could bookmark the page or share the link and their active session goes with it.

An attacker who gets that token can hijack the session. That's access to the donor's profile, payment info, and transaction history. For a nonprofit processing charitable donations, that's a direct PCI DSS compliance problem.

CWE 598 (Information Exposure Through Query Strings in GET Request) and CWE 384 (Session Fixation).

Recommended fix: Move session tokens to HTTP cookies with the Secure and HttpOnly flags. Use hidden form fields for CSRF tokens instead of URL parameters.


### Finding 2: Sessions persist after password change

Priority: High | Source: Manual testing

This one actually concerned us more than the session token issue. When you change your password on the donor profile page, the application doesn't kill your existing sessions.

We tested it step by step. Logged into the donor portal on two browsers at the same time. Changed the password on browser one. Went back to browser two and it was still fully active, we could still update profile info and everything. We got screenshots of the whole thing.

Think about what that means. A user thinks their account is compromised so they change their password. They think the attacker is locked out. But they're not. The old session is still valid. The whole point of changing your password is defeated.

Combine this with the session token being in URLs and you've got a scenario where an attacker can maintain access to donor accounts even after the victim takes action to protect themselves.

Recommended fix: Invalidate all sessions on password change. Force re-authentication with the new credentials. Add 2FA for sensitive account actions. Notify users when their password changes with time and location info.


### Finding 3: DOM based open redirection

Severity: Low | Confidence: Tentative | Instances: 4

Burp's dynamic analysis caught four instances of DOM based open redirection on the main site and a localized variant. The app was reading from location.href and passing it to xhr.send through a third-party analytics script.

An attacker could build a URL that starts with the legitimate domain but redirects to a malicious site. It looks trustworthy at first glance. That's dangerous for phishing, especially targeting donors. You could craft a convincing donation email with a link that starts with the real domain but sends people to a credential harvesting page.

Recommended fix: Whitelist permitted redirect targets. Validate URLs client-side before executing. Audit third party scripts for unintended data flow from user controllable sources to sensitive sinks.


### Finding 4: HSTS not enforced

Severity: Low | Confidence: Certain

No HSTS headers. The site wasn't telling browsers to enforce HTTPS only, which means users are open to downgrade attacks and man in the middle interception.

Think about a donor on public Wi-Fi at a coffee shop making a donation. Without HSTS, someone on the same network could intercept that traffic. Credentials, session tokens, personal info, all potentially exposed.

Recommended fix: Add the Strict-Transport-Security header with a reasonable max-age and the includeSubDomains flag.


### Finding 5: TLS cookies without secure flag

Cookies were being set without the Secure flag, meaning they could get transmitted over plain HTTP. Burp confirmed it in the response headers across multiple paths on the donor services subdomain.

If a user hits any HTTP page by accident, their session cookies are up for grabs. This makes the HSTS issue worse since there's nothing stopping the browser from making insecure requests in the first place.

Recommended fix: Set Secure, HttpOnly, and SameSite on all cookies, especially anything tied to sessions and auth.


### Finding 6: Infrastructure exposure through DNS

DNS recon showed that the donor services subdomain resolved to an IP owned by a third-party platform (confirmed via WHOIS). The SSL cert matched the organization's donor services.

The main domain was sitting behind a CDN, but this subdomain wasn't. The server IP was directly exposed. That means an attacker could skip the CDN entirely, bypass DDoS protection and WAF rules, and hit the server directly. Not great for a subdomain handling financial transactions.

Recommended fix: Route the subdomain through the CDN. Lock down the origin server to only accept traffic from the CDN's IP ranges.


### Finding 7: CMS infrastructure exposure

Burp and manual source review turned up a bunch of CMS-related issues.

Default admin and content paths were visible in the page source across JS and CSS references. The X-Powered-By header gave away the platform. That's free recon for an attacker targeting known CMS vulnerabilities.

The CMS cron handler was publicly accessible and returning 200 OK. We hit it with rapid requests through Burp's Proxy and confirmed it could accept them before throttling kicked in. That's a DoS vector.

Burp found 39 accessible backup files (.bak, .old, .bac extensions) across sitemaps, plugins, and theme files. Backup files can leak site structure, configs, and potentially sensitive data.

Missing X-Frame-Options meant the pages could be embedded in iframes on malicious sites. Clickjacking risk.

An internal IP address was leaking in response headers, giving away network architecture info.

Recommended fix: Obscure default CMS paths. Kill public access to the cron handler, use a server-side job instead. Delete all backup files from public directories. Add X-Frame-Options DENY or SAMEORIGIN. Strip internal IPs from response headers.


### Presenting the findings

This part is where I learned something you don't get from labs.

We put everything into a prioritized remediation table. Critical stuff at the top, informational at the bottom. Each finding had the vulnerability, the business impact, and a clear fix.

When we presented to leadership, the technical details weren't what moved them. It was the business impact. When we said an attacker could hijack a donor's payment session and access PCI cardholder data, the room got it. That's a trust problem. That's a funding problem. For a charity that runs on donor confidence, that's existential.

The session management issues got flagged for immediate attention. The migration team used our findings to shape the architecture of the new platform.

---

## Part 2: Lab Work

### Why PortSwigger

After the assessment I wanted to understand the mechanics better. I'd used Burp Suite to find real issues on a live system but I wanted to get deeper into the attack surface. PortSwigger's Web Security Academy is free, it's built by the Burp Suite team, and it covers everything with hands-on labs. I started with SQL injection and authentication because those are the most common vectors and directly relevant to what I'd already found.

### SQL injection labs

First lab was "SQL Injection Vulnerability in WHERE Clause Allowing Retrieval of Hidden Data." Shopping app with a category filter that builds a query like this:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The released = 1 hides unreleased products. I intercepted the request with Burp's Proxy and saw the category value going straight into the WHERE clause with no encoding or parameterization. That's a red flag every time.

I changed the category parameter to `'+OR+1=1--` which makes the condition always true and comments out the rest. App returned all products including hidden ones.

Second lab took it further. Modified the username to `administrator'--` and the password check gets commented out. App authenticates on username alone.

Same root cause as the real world findings. Session tokens in URLs, unsanitized SQL, passwords that don't kill sessions. The application trusts data it shouldn't. Everything I found in the assessment and every lab I've done traces back to that.

### Authentication vulnerabilities

I've been working through PortSwigger's authentication module too. Brute force, credential stuffing, flawed session management. The session handling material connected directly to what I found in the assessment. Going through those labs after already finding the same issues on a live system made it click in a way that just reading about it never would.

---

## Lessons learned

1. Real findings come from manual testing. Burp found 84 issues but the biggest one, sessions persisting after password change, came from manual testing and understanding how the app actually works. Tools find vulnerabilities. Testers prove impact.

2. Answer the "so what." A session token in a URL means nothing to a non-technical stakeholder. "An attacker could hijack a donor's payment session and access PCI cardholder data" means everything. If you can't translate technical severity into business risk the finding isn't actionable.

3. Lab practice builds instincts. PortSwigger taught me to think about data flow through an application. That same mindset led to the most significant findings in the live assessment.

4. Communication matters as much as technical skill. Presenting to a nonprofit's leadership meant translating severity into business risk. A prioritized remediation table with impact statements was more useful to them than raw scan output.

5. Protect your clients. Everything identifying has been removed from this writeup. No org names, no URLs, no infrastructure specifics. That's not optional. That's the foundation of the trust that makes this work possible.

---

## Tools used

- [Burp Suite](https://portswigger.net/burp) for web vulnerability scanning, request interception, and manual testing
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) for hands on labs
- [Nmap](https://nmap.org/) for network reconnaissance
- [Nikto](https://github.com/sullo/nikto) for web server vulnerability scanning
- [OWASP ZAP](https://www.zaproxy.org/) for additional web application testing
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) as reference for web security risks

---

## About me

Cybersecurity professional based in Toronto. MS in Information Systems Security Management from Northeastern University. Experience in SOC operations, penetration testing, and web application security assessments. Active in the OWASP community, building offensive security skills through PortSwigger Web Security Academy and HackTheBox.

[LinkedIn](https://www.linkedin.com/in/ayaan-m-2643122a0/)

---

*This writeup reflects authorized security assessment work. All client identifying information has been removed to protect organizational privacy. No sensitive data was accessed or exfiltrated during the assessment.*
