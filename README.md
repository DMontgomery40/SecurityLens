# SecurityLens 
An open-source security analysis platform for education and vulnerability discovery.

https://securitylens.netlify.app/

## Current Features

- Static code analysis for common security vulnerabilities
- Pattern-based vulnerability detection
- Detailed explanations and recommendations
- Detection of 32 vulnerabilities (full list and detection pattern below)
- View by Severity Level, further filter by Vulnerability Type or File

## Detected Vulnerabilities

Below is the list of vulnerabilities that **SecurityLens** scans for:

| **Vulnerability**                           | **Description**                                                                                   | **Severity** | **CWE**   |
|---------------------------------------------|---------------------------------------------------------------------------------------------------|--------------|-----------|
| **Dangerous Code Execution**                | Dangerous code execution via `eval()` or Function constructor                                   | CRITICAL     | CWE-95    |
| **Command Injection**                       | Potential command injection vulnerability                                                        | CRITICAL     | CWE-77    |
| **Authentication Bypass**                   | Authentication bypass or missing authentication                                                 | CRITICAL     | CWE-306   |
| **Hardcoded Credentials**                   | Hardcoded credentials detected                                                                    | CRITICAL     | CWE-798   |
| **SQL Injection**                           | Potential SQL injection vulnerability                                                            | CRITICAL     | CWE-89    |
| **Cross-site Scripting (XSS)**              | Cross-site scripting vulnerability                                                               | HIGH         | CWE-79    |
| **NoSQL Injection**                         | Potential NoSQL injection vulnerability                                                          | CRITICAL     | CWE-943   |
| **Weak Cryptographic Hash**                 | Use of weak cryptographic hash function                                                          | HIGH         | CWE-326   |
| **Deprecated Cryptographic Functions**      | Use of deprecated cryptographic functions                                                        | HIGH         | CWE-927   |
| **Unsafe Buffer Allocation**                | Unsafe buffer allocation                                                                          | HIGH         | CWE-119   |
| **Memory Leak in Timer/Interval**           | Potential memory leak in timer/interval                                                           | MEDIUM       | CWE-401   |
| **Sensitive Data Exposure**                 | Sensitive data exposure                                                                           | HIGH         | CWE-200   |
| **Insecure Data Transmission**              | Potential insecure data transmission                                                              | MEDIUM       | CWE-319   |
| **Sensitive Information in Errors**         | Potential sensitive information in error messages                                                | MEDIUM       | CWE-209   |
| **Insecure Direct Object Reference (IDOR)**  | Potential Insecure Direct Object Reference (IDOR)                                                 | HIGH         | CWE-639   |
| **Improper Authorization Checks**           | Improper authorization checks allowing unauthorized access                                       | CRITICAL     | CWE-306   |
| **Path Traversal**                          | Potential path traversal vulnerability                                                           | HIGH         | CWE-23    |
| **Unsanitized Input Usage**                 | Unsanitized user input used in sensitive operations                                              | HIGH         | CWE-932   |
| **Open Redirect**                           | Potential open redirect vulnerability                                                             | MEDIUM       | CWE-601   |
| **Resource Leak**                           | Potential resource leak due to synchronous file operations                                       | MEDIUM       | CWE-399   |
| **Session Fixation**                        | Potential session fixation vulnerability allowing attacker to set session ID                      | HIGH         | CWE-384   |
| **Insecure Session Storage**                | Insecure session storage without secure flags                                                     | HIGH         | CWE-925   |
| **Server-Side Request Forgery (SSRF)**      | Potential SSRF vulnerability from user-supplied input in request calls                           | CRITICAL     | CWE-918   |
| **Insecure API Setup**                      | Potential insecure API setup without proper authentication middleware                             | HIGH         | CWE-921   |
| **JWT in URL**                              | JWT token present in URL instead of headers                                                        | HIGH         | CWE-922   |
| **Token in URL**                            | Authentication token present in URL parameters                                                    | HIGH         | CWE-923   |
| **Weak Rate Limiting**                      | Potentially weak rate limiting configuration in API setup                                         | MEDIUM       | CWE-924   |
| **Missing or Misconfigured CORS**           | Missing or misconfigured CORS in API setup                                                        | MEDIUM       | CWE-925   |
| **Insecure Middleware Setup**               | Insecure middleware setup allowing unauthorized access                                            | HIGH         | CWE-926   |
| **Vulnerable Dependencies**                 | Vulnerable dependencies detected in `package.json`                                                | HIGH         | CWE-925   |
| **Outdated Dependencies**                   | Outdated dependencies detected in `package.json`                                                  | MEDIUM       | CWE-926   |

## Roadmap

### Phase 1 (Current)
{: .no_toc }

- [x] Basic vulnerability scanning
- [x] CVE database integration
- [ ] Dependency vulnerability checking

### Phase 2 (Future)
{: .no_toc }

- [ ] Binary analysis capabilities
- [ ] Integration with reverse engineering tools
- [ ] Interactive learning modules

### Phase 3 (Long-term)
{: .no_toc }

- [ ] Collaborative analysis features
- [ ] Integration with additional security tools
- [ ] Advanced binary analysis

## Current Results Page Example

![SecurityLens Screenshot](/assets/security-lens-screenshot.png)
{: .text-center }
