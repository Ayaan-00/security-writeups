# Web Application Security Assessment: Session Management and Authentication Vulnerabilities in a Nonprofit Donor Platform

Ayaan Mohammed

Tools: Burp Suite, Nmap, Nikto, OWASP ZAP | Lab Platform: PortSwigger Web Security Academy

---

## Background

There is a moment during every security assessment where a finding stops being academic and starts being real. For me, that moment came while running Burp Suite against a children's charity's donor platform and realizing that a session token sitting in a URL meant an attacker could hijack a donor's payment session.

That finding changed how I think about web application security. It was not about the technical complexity. It was about the 1.5 million active donors whose trust depended on that application being secure.

This writeup walks through that experience. It starts with the real world, because that is where the stakes are. Then it connects back to PortSwigger Web Security Academy where I have been building the foundational skills that made those findings possible. The goal here is to show how lab practice translates into real impact, and why answering "so what" matters more than just finding the vulnerability.

---

## Part 1: The Real World Assessment

### How it started

While working as a Security Project Assistant at a Canadian nonprofit organization, I was part of a small team conducting a security assessment during a website migration project. This organization serves a vulnerable population and manages a donor platform with over 1.5 million active supporters. Their systems process financial transactions and store personally identifiable information, making them subject to PCI DSS compliance requirements.

The project started as a website migration from WordPress to a new platform. Our team was responsible for evaluating the existing web application for security gaps before the transition. What we found went well beyond what we expected going in.

This assessment was conducted with explicit authorization from the organization's leadership. All findings were reported through proper channels. No data was exfiltrated or accessed beyond the scope of the assessment.

### How we set up

We used Burp Suite to perform a light scan of the organization's public facing website and its secure donor services subdomain. On top of that we conducted manual testing of the authentication and session management features, DNS reconnaissance to map the infrastructure, and Nikto scans for server level misconfigurations.

The approach was pretty methodical. Start broad with automated scanning, then go deeper on anything that looks interesting. That "go deeper" part is where the real findings came from.

### Findings overview

The Burp Suite scan returned 1 medium severity issue, 5 low severity issues, and 78 informational items across the application. Manual testing uncovered additional high priority authentication weaknesses that the automated scan did not catch. Below are the findings that carried the most business impact.


### Finding 1: Session token exposed in donation URL

Severity: Medium | Confidence: Firm

This was the finding that changed everything for me.

The donor facing payment portal embedded a session identifier (jsessionid) directly in the URL of the donation page. Burp flagged this during the automated scan on the French language donation path. The session token was being appended to the payment form link alongside Google Analytics tracking parameters and a nonce token.

To someone who is not in security, that might sound harmless. But here is what it actually means. That session token shows up in browser history. It gets logged on the web server. It gets sent to third party services through the HTTP Referer header every time the page loads an external resource like analytics scripts or ad tracking pixels. A donor could bookmark the page or share the link without realizing their active session is attached to it.

If an attacker obtains that session token they can hijack the donor's session. That means access to the donor's profile, payment information, and transaction history. For an organization processing charitable donations this is a direct PCI DSS compliance risk.

This falls under CWE 598 (Information Exposure Through Query Strings in GET Request) and CWE 384 (Session Fixation).

Recommended fix: Transmit session tokens exclusively through HTTP cookies with the Secure and HttpOnly flags set, not in URLs. Implement anti CSRF tokens through hidden form fields rather than URL parameters.


### Finding 2: Sessions persist after password change

Priority: High | Source: Manual testing

During manual testing we discovered something that concerned us even more. Changing a user's password on the donor profile page did not invalidate existing sessions.

We verified this step by step. We logged into the donor portal on two separate browsers at the same time. Changed the password on one browser. Then checked the other browser and confirmed the session was still fully active, including the ability to modify profile information. We documented all of this with screenshots showing the password change confirmation on one side and a successful profile update on the other using the old session.

Think about what this means in practice. A user suspects their account has been compromised. They change their password expecting that will lock the attacker out. But it does not. The attacker's session remains valid. The security purpose of a password change is completely undermined.

Combined with the session token exposure in URLs this creates a scenario where an attacker could maintain persistent access to donor accounts even after the victim takes protective action.

Recommended fix: Implement session invalidation upon password change. All active sessions should be terminated requiring re authentication with the new credentials. Implement two factor authentication for sensitive account actions. Send immediate notifications to users when their password is changed including time and location details.


### Finding 3: DOM based open redirection

Severity: Low | Confidence: Tentative | Instances: 4

Burp's dynamic analysis identified four instances of DOM based open redirection across the main site and its French language variant. The application read data from location.href and passed it to xhr.send through a LinkedIn analytics script.

An attacker could construct a URL that when visited by a donor redirects them to a malicious site. Because the URL starts with the legitimate domain it passes visual inspection and appears trustworthy. This is especially dangerous for phishing attacks targeting donors. Attackers could craft convincing donation request emails with links that start with the real domain but redirect to a credential harvesting page.

Burp confirmed this through dynamic analysis by injecting test values into the URL parameters and observing them reach the xhr.send sink through the LinkedIn tracking script execution path.

Recommended fix: Implement a whitelist of permitted redirection targets and validate all redirection URLs against it on the client side before executing. Review third party scripts for unintended data flow from user controllable sources to sensitive sinks.


### Finding 4: HSTS not enforced

Severity: Low | Confidence: Certain

The application failed the HTTP Strict Transport Security test. Without HSTS headers the site does not instruct browsers to enforce HTTPS only connections which leaves users vulnerable to downgrade attacks and man in the middle interception.

Picture a donor sitting in a coffee shop connected to public Wi Fi making a donation. Without HSTS an attacker on the same network could intercept the traffic between the donor and the application. Login credentials, session tokens, personal information, all potentially visible.

Recommended fix: Configure the web server to include the Strict Transport Security header with a reasonable max age directive and the includeSubDomains flag.


### Finding 5: TLS cookies without secure flag

Several cookies were set without the Secure flag meaning they could be transmitted over unencrypted HTTP connections. Burp confirmed this in the response headers where session cookies were being set for multiple paths on the donor services subdomain without consistent Secure flag enforcement.

If a user accidentally accesses any HTTP page, session cookies could be intercepted and used for session hijacking. This compounds the risk from the missing HSTS headers since there is no mechanism preventing the browser from making insecure requests.

Recommended fix: Set the Secure, HttpOnly, and SameSite attributes on all cookies. Especially those related to session management and authentication.


### Finding 6: Infrastructure exposure through DNS

DNS reconnaissance revealed that the secure donor services subdomain resolved to an IP address owned by a third party donor management platform (identified through WHOIS lookup). The SSL certificate confirmed the subdomain was registered to the organization's donor services unit.

Unlike the main domain which was protected behind Cloudflare's CDN (confirmed by the CF Ray response headers in Burp), this subdomain's server IP was directly exposed. This means attackers could bypass CDN level protections like DDoS mitigation and WAF rules and target the underlying server directly. Particularly concerning for a subdomain that processes financial transactions.

Recommended fix: Route the subdomain through the CDN proxy service to mask the origin server IP. Ensure the origin server only accepts connections from the CDN's IP ranges.


### Finding 7: WordPress infrastructure exposure

The Burp scan and manual source code review revealed several WordPress specific exposures.

Source code paths visible: Default WordPress paths (wp content, wp admin, wp includes) were visible in the page source across multiple JavaScript and CSS file references. The X Powered By header confirmed the hosting platform. This gives attackers structural information for targeted attacks against known WordPress vulnerabilities.

wp cron.php publicly accessible: The WordPress cron handler was accessible via direct web request and returned a 200 OK response. We confirmed this through Burp's Proxy by sending a GET request to the endpoint. Using a stress testing tool we verified that the endpoint could accept rapid successive requests before being throttled confirming a potential denial of service vector.

Backup files accessible: Burp identified 39 instances of accessible backup files across sitemap files, plugin files, and theme files. These included .bak, .old, and .bac extensions for sitemaps, pages, posts, and theme JavaScript bundles. Accessible backup files can reveal site structure, plugin configurations, and potentially sensitive data.

Frameable response: Missing X Frame Options headers allowed the application pages to be embedded in iframes on malicious sites. An attacker could overlay the legitimate donation page with a transparent malicious layer tricking donors into performing unintended actions.

Private IP address disclosed: The scan detected an internal IP address being disclosed in response headers providing attackers with information about the internal network architecture.

Recommended fix: Change or obscure default WordPress paths using security plugins. Disable web access to wp cron.php and implement a server side cron job. Remove all backup files from publicly accessible directories. Add X Frame Options DENY or SAMEORIGIN headers. Strip internal IP addresses from response headers.


### Presenting the findings

Here is where I learned something that no lab teaches you.

We compiled every finding into a prioritized remediation table. High priority items like session management, HSTS, and cookie security at the top. Informational items at the bottom. Each finding included the vulnerability, its business impact, and a clear recommended fix.

When we presented to the organization's leadership the technical details were not what moved them. It was the "so what." When we explained that an attacker could hijack a donor's payment session and potentially access PCI cardholder data for their 1.5 million active supporters, the room understood. That is a trust issue. That is a funding issue. That is an existential risk for a charity that depends on donor confidence.

The critical session management issues were flagged for immediate attention. The migration team incorporated our findings into the architecture of the new platform.

---

## Part 2: Lab Work and Foundations

### Why PortSwigger

After the nonprofit assessment I wanted to go deeper into the mechanics of web application vulnerabilities. I had used Burp Suite to find issues on a live system but I wanted to understand the attack surface at a more granular level. That is what brought me to PortSwigger's Web Security Academy.

The Academy is free, built by the same people who made Burp Suite, and it covers the full spectrum of web vulnerabilities with hands on labs. I started with SQL injection and authentication vulnerabilities because those are the most common attack vectors and directly relevant to the types of findings I encountered.

### SQL injection labs

The first lab I completed was "SQL Injection Vulnerability in WHERE Clause Allowing Retrieval of Hidden Data." A shopping application uses a product category filter that builds a SQL query:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The released = 1 condition hides unreleased products. When I intercepted the request with Burp Suite's Proxy I could see the category value being placed directly into the WHERE clause with no encoding or parameterization. User input going straight into a SQL query is always a red flag.

I modified the category parameter to `'+OR+1=1--` which creates a condition that is always true and comments out the rest of the query. The application returned all products including hidden ones.

The second lab took this further. By modifying the username parameter to `administrator'--` the password check gets commented out entirely and the application authenticates based on the username alone.

These labs reinforced something I already understood from the real world assessment. Whether it is session tokens in URLs, unsanitized SQL queries, or passwords that do not invalidate sessions, the root cause is the same: the application trusts data it should not trust. Every vulnerability I found at the nonprofit and every lab I have completed traces back to that principle.

### Authentication vulnerabilities

I have also been working through PortSwigger's authentication module covering how password based login systems can be exploited through brute force attacks, credential stuffing, and flawed session management.

The material on session handling connected directly to what I found at the nonprofit. The lab explains how session tokens should be managed, what happens when they are exposed, and why proper invalidation matters. Working through this after having already discovered those exact issues in a live environment made the concepts click in a way that purely academic learning never could.

---

## Lessons learned

1. Real findings come from manual testing. Burp Scanner identified 84 issues across the application. But the most impactful finding, sessions persisting after password change, came from manual testing and understanding the application's logic. Tools find vulnerabilities. Testers prove impact.

2. Always answer the "so what." A session token in a URL means nothing to a nontechnical stakeholder. "An attacker could hijack a donor's payment session and access PCI cardholder data" means everything. Translating technical severity into business risk is what makes a finding actionable.

3. Lab practice builds real world instincts. PortSwigger Academy taught me to think about how data flows through an application. That same mindset is exactly what led to the most significant findings in the live assessment.

4. Client communication matters as much as technical skill. Presenting findings to a nonprofit's leadership requires translating technical severity into business risk. A prioritized remediation table with clear impact statements was more valuable to them than raw scan output.

5. Protect your clients. Every piece of identifying information has been removed from this writeup. No organization names, no URLs, no infrastructure details. That is not just good practice. It is the foundation of the trust that makes security work possible.

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

Cybersecurity professional based in Toronto. MS in Information Systems Security Management from Northeastern University. My experience includes SOC operations, penetration testing, and web application security assessments across multiple sectors. Active participant in the OWASP community, currently building offensive security skills through PortSwigger Web Security Academy and HackTheBox.

[LinkedIn](https://www.linkedin.com/in/ayaan-m-2643122a0/)

---

*This writeup reflects authorized security assessment work. All client identifying information has been removed to protect organizational privacy. No sensitive data was accessed or exfiltrated during the assessment.*
