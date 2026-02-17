# Web Server Vulnerability Scanning with Nikto: Security Header Analysis and Attack Surface Mapping on OWASP Juice Shop

Ayaan Mohammed | February 2025

Tools: Nikto, Docker, Kali Linux | Target: OWASP Juice Shop (localhost lab environment)

---

## Why This Matters

Web application penetration testing usually starts with the application layer. Login forms, session management, input validation. But before any of that, there is the server itself. Misconfigured headers, exposed directories, leftover backup files, verbose error responses. These are the things attackers look for first because they require zero authentication and they map the attack surface before a single exploit is written.

This writeup walks through a Nikto scan against OWASP Juice Shop running in a local Docker container. The goal was not just to run a scanner and copy the output. It was to understand what each finding means, why it matters, and how an attacker would use it to plan their next move. That distinction, treating scan results as intelligence rather than a checklist, is what separates automated scanning from actual security assessment.

---

## The Setup

OWASP Juice Shop is a deliberately vulnerable web application maintained by the OWASP Foundation. It is designed to contain real world vulnerability classes including broken authentication, injection flaws, security misconfigurations, and sensitive data exposure. Running it locally in Docker creates a safe, legal environment to practice offensive techniques without touching production systems.

The environment was straightforward. Kali Linux running in VirtualBox, Docker installed and running, Juice Shop pulled and deployed on port 3000. Nikto comes preinstalled on Kali, so no additional configuration was needed.

```bash
sudo docker run -d -p 3000:3000 bkimminich/juice-shop
```

Once the container was up, I confirmed the application was accessible at `http://localhost:3000` before starting the scan.

---

## Running the Scan

I ran two scans. The first was a baseline scan against the default Apache web server on port 80 to establish what Nikto reports on a standard configuration. The second was the targeted scan against Juice Shop on port 3000.

```bash
nikto -h http://localhost:3000
nikto -h http://localhost:3000 -o nikto_juiceshop_results.txt
```

The second command saved the output to a text file for post-scan analysis. In a real engagement, this is standard practice. Scan output goes into the evidence file alongside Burp logs, Nmap results, and manual testing notes. Everything gets documented.

---

## Findings

### 1. Missing Security Headers

Nikto identified that two critical security headers were absent from the application's HTTP responses.

**X-Frame-Options** was not set. This header controls whether a browser allows a page to be rendered inside an iframe. Without it, an attacker can embed the application inside a malicious page and overlay invisible elements on top of legitimate buttons and forms. The victim thinks they are clicking on the real application but they are actually interacting with the attacker's page. This is clickjacking, and it is particularly effective against applications that handle financial transactions or account settings.

**X-Content-Type-Options** was not set. This header prevents browsers from guessing the MIME type of a response. Without it, a browser might interpret a text file as executable JavaScript, which opens the door to content injection attacks. An attacker who can upload or reference a file with ambiguous content type could trick the browser into executing it as code.

These are not theoretical risks. They are among the most commonly exploited misconfigurations in web applications. OWASP includes security header misconfiguration under its Top 10 (A05:2021 Security Misconfiguration).

**Remediation:** Configure the web server to include `X-Frame-Options: DENY` or `SAMEORIGIN` and `X-Content-Type-Options: nosniff` in all HTTP responses. In production, also implement a Content Security Policy header for defense in depth.

### 2. Exposed Directory via robots.txt

Nikto detected that the `/robots.txt` file disclosed a `/ftp/` directory, and that directory returned an HTTP 200 status code, meaning it was publicly accessible.

The `robots.txt` file tells search engine crawlers which paths to avoid indexing. But it is publicly readable by anyone, not just crawlers. Attackers routinely check `robots.txt` as one of their first reconnaissance steps because it often reveals directories the developers wanted hidden from search results but forgot to actually restrict access to.

In this case, the `/ftp/` directory being accessible means an attacker can browse its contents directly. Depending on what is stored there, this could expose configuration files, database dumps, internal documentation, or application source code. The directory name itself suggests file transfer functionality, which often contains sensitive uploads or downloads.

**Remediation:** Never rely on `robots.txt` for security. Implement proper access controls on all sensitive directories. Use authentication requirements, IP whitelisting, or remove the directories from the web root entirely.

### 3. Uncommon Header Disclosure (x-recruiting)

Nikto flagged an uncommon header: `x-recruiting` with contents pointing to `/#/jobs`.

This is specific to Juice Shop, which is intentionally playful. But the finding illustrates a real principle. Custom HTTP headers leak information about the application's purpose, internal structure, or technology stack. In a production environment, headers like `X-Powered-By`, `X-Debug-Token`, or custom application identifiers give attackers clues they can use to fingerprint the application and research known vulnerabilities for that specific technology.

During the real world nonprofit assessment I conducted separately, I encountered a similar situation where the `X-Powered-By` header confirmed the CMS platform, which allowed me to immediately narrow my testing to known vulnerability classes for that platform.

**Remediation:** Remove or suppress all unnecessary custom headers in production. Configure the web server to strip headers that reveal technology stack, debug information, or internal application details.

### 4. Backup and Certificate Files Accessible

Nikto identified several potentially sensitive files that returned valid HTTP responses:

- `backup.tar.lzma` — compressed backup archive
- `database.tar` — database backup archive
- `127.0.0.1.egg` — Python egg package
- `site.egg` — Python egg package
- `localhost.cer` — SSL certificate file

These findings reference CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere). Backup files are one of the highest value targets in reconnaissance because they often contain database credentials, API keys, application source code, and configuration files that are not meant to be public.

A `database.tar` file accessible over HTTP is particularly severe. If that file contains a database dump, an attacker has the full dataset without needing to exploit a single vulnerability in the running application. The SSL certificate file could reveal internal hostnames, certificate authority details, or private key material depending on what was bundled.

**Remediation:** Remove all backup files, archives, and certificate files from the web root. Implement automated checks in the deployment pipeline that flag non-application files in publicly accessible directories. Store backups in isolated, access-controlled storage.

### 5. Server Information Leakage via ETags

Nikto detected that the server may be leaking inode information through ETag headers. ETags are used for HTTP cache validation, but when configured to include inode numbers, they reveal details about the server's file system structure.

This information is useful for server fingerprinting. An attacker can use inode values to identify the operating system, file system type, and potentially distinguish between servers in a load-balanced environment. Combined with other reconnaissance data, it helps build a precise picture of the target infrastructure.

**Remediation:** Configure the web server to generate ETags without inode information, or use alternative cache validation mechanisms.

### 6. Wildcard Access-Control-Allow-Origin

Nikto retrieved an `access-control-allow-origin: *` header, meaning the application allows cross-origin requests from any domain.

This is a CORS (Cross-Origin Resource Sharing) misconfiguration. When set to wildcard, any website can make authenticated requests to the application on behalf of a logged-in user. If the application also reflects credentials in cross-origin responses, an attacker could host a malicious page that silently queries the vulnerable application and exfiltrates user data.

**Remediation:** Replace the wildcard with an explicit whitelist of trusted origins. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.

---

## Baseline Comparison: Default Apache on Port 80

The scan against the default Apache server on port 80 provided useful context. That scan returned five items: missing X-Frame-Options, missing X-Content-Type-Options, ETag inode leakage, allowed HTTP methods (POST, OPTIONS, HEAD, GET), and an exposed `/server-status` endpoint.

The `/server-status` finding is worth noting. This is an Apache module that displays real-time server performance data including active requests, client IPs, and request URIs. In a production environment, leaving this publicly accessible gives an attacker a live view of the server's traffic patterns and connected clients.

Comparing the two scans highlighted something important. The default Apache server and the Juice Shop application shared some of the same misconfigurations (missing security headers, ETag leakage). This means these issues are often inherited from the web server's default configuration rather than introduced by the application code. A secure deployment needs to address both layers.

---

## Connecting Scanning to Assessment

Running Nikto is the easy part. The value is in what you do with the results.

Every finding from this scan maps to a next step in a real engagement. Missing security headers get flagged in the report and tested for exploitability with manual clickjacking or content injection attempts. Exposed directories get browsed for sensitive content. Backup files get downloaded and examined for credentials. Uncommon headers get cross-referenced against known technology fingerprints. None of these findings exist in isolation. They are data points that feed into the broader assessment.

This is something I learned during my first real world security assessment. Nikto ran alongside Burp Suite, Nmap, and manual testing against a nonprofit's donor platform. Nikto caught the server-level misconfigurations. Burp caught the application-level vulnerabilities. Manual testing caught the logic flaws that neither tool detected. The complete picture only emerged when all three layers were combined.

Nikto is a detection tool, not an exploitation tool. It tells you where to look. The tester decides what to do with that information.

---

## Tools and References

| Tool | Purpose |
|------|---------|
| [Nikto](https://github.com/sullo/nikto) | Open source web server vulnerability scanner |
| [Docker](https://docs.docker.com/) | Container platform for deploying isolated test environments |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | Deliberately vulnerable web application for security training |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Industry standard classification of web application security risks |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File to an Unauthorized Control Sphere |
| [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | Protection Mechanism Failure (security header misconfiguration) |

---

## About Me

Cybersecurity professional based in Toronto. MS in Information Systems Security Management from Northeastern University. My experience includes SOC operations, penetration testing, and web application security assessments across multiple sectors. Active participant in the OWASP community, building offensive security skills through PortSwigger Web Security Academy and HackTheBox.

[LinkedIn](https://www.linkedin.com/in/ayaan-m-2643122a0/)

---

*This writeup documents a scan performed against a locally hosted, intentionally vulnerable application in a controlled lab environment. No production systems were tested. OWASP Juice Shop is designed for security education and training purposes.*
