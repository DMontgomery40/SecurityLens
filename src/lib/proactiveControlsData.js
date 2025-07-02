// Example "proactive controls" data (some may be unused if you only show them in InfoPanel)
const proactiveControlsData = {
  C7_ACCESS_CONTROLS: `
    <h3>C7: Enforce Access Controls</h3>
    <p>
      Access Control (Authorization) is the process of granting or denying specific requests 
      from a user, program, or process. Failure to implement proper access control 
      can lead to unauthorized disclosure, modification, or destruction.
    </p>
    <ul>
      <li>Enforce checks consistently</li>
      <li>Use deny by default</li>
      <li>Implement RBAC</li>
    </ul>
  `,

  vulnerabilityGuides: {
    sqlInjection: {
      title: "A03:2021 - SQL Injection",
      content: `
        <h3>SQL Injection Overview</h3>
        <p>
          SQL injection can allow attackers to read, modify, or delete database data by injecting malicious SQL into queries.
        </p>
        <ul>
          <li>Use parameterized queries or prepared statements</li>
          <li>Never concatenate user input into SQL strings</li>
          <li>Validate and sanitize all inputs</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> These instructions are provided <em>only</em> for educational use on systems you own or have explicit written permission to test.</p>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step&nbsp;1 – Build Your Kali&nbsp;Lab</a> to create an isolated VM / container with the required tooling.</p>
        <ol start="2">
          <li><strong>Enumerate &amp; Map the Application</strong> – Launch the GUI version of <em>OWASP&nbsp;ZAP</em> and run the "Automated&nbsp;Scan". Save the sitemap and generate a context file for later brute-force testing.</li>
          <li><strong>Discover Unprotected Resources</strong> – From ZAP choose "Forced Browse", load <code>/usr/share/wordlists/dirb/common.txt</code>, and scan for hidden URLs such as <code>/admin</code>, <code>/actuator</code>, <code>/api/v1/users</code>. Flag every unexpected HTTP 200/302.</li>
          <li><strong>Horizontal Privilege Escalation</strong> – Using <em>Burp Suite Community</em> proxy, log in as a normal user, intercept a request to <code>/api/v1/users/&lt;id&gt;</code>, send to Repeater, then iterate IDs (e.g., with sequence <code>1..25</code>). Any response that exposes another user's data indicates broken object-level access control (BOLA).</li>
          <li><strong>Vertical Privilege Escalation</strong> – Add the <em>AuthMatrix</em> extension. Define roles "guest", "user", "support", "admin". Import previously captured traffic and run "Generate Matrix". Green cells outside their role indicate missing role enforcement.</li>
          <li><strong>Bypass Tricks</strong> – Attempt:
            <ul>
              <li>HTTP verb tampering (<code>DELETE</code> → <code>GET</code>, etc.)</li>
              <li>Path traversal/encoding (<code>..%2Fadmin</code>, double slashes)</li>
              <li>Header overrides (<code>X-Original-URL</code>, <code>X-Forwarded-For: '127.0.0.1'</code>)</li>
            </ul>
            Record any request that evades the control.</li>
          <li><strong>Session Fixation &amp; Prediction</strong> – With Burp Intruder, fuzz captured session cookies and monitor for collisions that return HTTP 200.</li>
          <li><strong>Reporting</strong> – For each finding include: vulnerable endpoint, crafted request (as cURL), server response, affected role, and business impact.</li>
        </ol>
        <p><em>Next Step:</em> Convert your manual tests into an <code>autorize</code> plugin policy for continuous regression testing.</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / ASP.NET Core</h4>
        <ol>
          <li><strong>Centralised Authorisation</strong> – Implement policy-based RBAC:<pre class="code-block"><code>services.AddAuthorization(o =>
{
  o.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
});
[Authorize("AdminOnly")]
public IActionResult AdminArea() => Ok();</code></pre></li>
          <li><strong>Verbose Authorisation Logging</strong> – In <code>appsettings.Production.json</code> set <code>"Microsoft.AspNetCore.Authorization": "Information"</code> and forward <code>Application</code> logs to Microsoft Sentinel.</li>
          <li><strong>Sentinel Detection Rule</strong> – KQL:<br/><code>AppTraces | where Message has "/admin" and HttpStatus == 200 and UserId != "Admin"</code></li>
          <li><strong>WAF Enforcement</strong> – Deploy Azure WAF v2 with OWASP CRS 3.3; raise anomaly threshold to 5 and enable rule 931120 (path traversal).</li>
          <li><strong>CI Tests</strong> – Add xUnit integration tests using <code>WebApplicationFactory</code> to assert every protected endpoint returns 403 for unauthenticated users.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / Apache + PHP</h4>
        <ol>
          <li><strong>Enable ModSecurity v3 + OWASP CRS</strong> – Install via Homebrew, include the CRS, and enable rules 932100-932130 for access-control bypass detection.</li>
          <li><strong>Laravel/Symfony Gates</strong> – Define central gates/policies and use middleware groups to guard every route:<pre class="code-block"><code>Gate::define('admin', fn($u) => $u->isAdmin());
Route::middleware('can:admin')->group(function(){ Route::get('/admin', ...); });</code></pre></li>
          <li><strong>Real-Time Monitoring</strong> – Use <code>osquery</code>:<pre class="code-block"><code>SELECT datetime, uri, status FROM apache_access 
WHERE status = 200 AND uri LIKE '/admin%';</code></pre>Ship results to Wazuh for alerting.</li>
          <li><strong>Audit &amp; Review</strong> – Run <code>lynis audit system --tests-from-group authentication authorization</code> weekly.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Nginx / Node.js</h4>
        <ol>
          <li><strong>Reverse-Proxy ACL</strong> – In Nginx:<pre class="code-block"><code>map $cookie_role $acl { default 0; ~*admin 1; }
location /admin {
  if ($acl = 0) { return 403; }
  proxy_pass http://backend;
}</code></pre></li>
          <li><strong>Node.js RBAC</strong> – Employ <code>casl</code> or <code>express-jwt-permissions</code> to enforce permissions in code.</li>
          <li><strong>Elastic SIEM Rule</strong> – KQL:<br/><code>url.path : "/admin*" and response.status_code == 200 and user.name != "admin"</code></li>
          <li><strong>Continuous Scans</strong> – Daily <code>nikto</code>/<code>naabu</code> scheduled via cron; alert on any new HTTP 200 for restricted paths.</li>
          <li><strong>Container Hardening</strong> – Run Node inside a non-root user container with <code>readOnlyRootFilesystem: true</code>.</li>
        </ol>
      `
    },

    xssVulnerability: {
      title: "A03:2021 - Cross-Site Scripting (XSS)",
      content: `
        <h3>XSS Attack Overview</h3>
        <p>
          Cross-Site Scripting allows attackers to execute malicious scripts in users' browsers.
        </p>
        <ul>
          <li>Use content security policy (CSP)</li>
          <li>Encode/escape all user input</li>
          <li>Use safe JavaScript frameworks/libraries (modern frameworks like React, Vue, and Angular are safer by default, as they escape content automatically)</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> These instructions are provided <em>only</em> for authorised testing in a lab environment you control.</p>
        <p>Begin with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step&nbsp;1 – Build Your Kali&nbsp;Lab</a>.</p>
        <ol start="2">
          <li><strong>Map Reflection Points</strong> – In <em>Burp Suite Community</em> activate "Intercept". Browse the target normally and send every request that echoes user input to Burp Repeater. Note parameters such as <code>search</code>, <code>comment</code>, <code>msg</code>.</li>
          <li><strong>Quick Context Test</strong> – In Repeater inject <code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code>. Observe if it reaches the rendered HTML. If blocked, try <code>&lt;img src=x onerror=alert(1)&gt;</code>.</li>
          <li><strong>Determine Context</strong> – If the payload is HTML-escaped, switch to attribute-breakout vectors such as <code>" onmouseover=alert(1) autofocus="</code>. For JS string contexts, use <code>'-alert(1)-'</code>.</li>
          <li><strong>Automated Fuzzing</strong> – Load the <em>Turbo Intruder</em> extension and fire a word-list of XSS polyglots (e.g., <code>secLists/Fuzzing/XSS/xss-fuzz.txt</code>). Sort by "length diff" to locate reflections.</li>
          <li><strong>DOM-Based XSS</strong> – Open the browser dev-tools "Sources → Event Listener Breakpoints → DOM Mutation". Inject a payload into the URL hash <code>#xss=</code> and watch for JavaScript that writes <code>location.hash</code> to <code>innerHTML</code>.</li>
          <li><strong>Bypass Modern Defences</strong>
            <ul>
              <li>Content-type confusion: append <code>\u0000</code> characters.</li>
              <li>Inline JS event chains: <code>&lt;svg/onload=alert(1)&gt;</code></li>
              <li>If CSP is present: look for JSONP / <code>unsafe-inline</code> or find a whitelisted domain that you can control.</li>
            </ul>
          </li>
        </ol>
        <p><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</p>
        <p><em>What to try next:</em> Can you execute a script in another user's browser? What happens if you use different payloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / ASP.NET Core</h4>
        <ol>
          <li><strong>Enable XSS Detection in IIS</strong> – In <code>web.config</code> set <code>requestFiltering enableDoubleEscaping="false"</code> and <code>httpRuntime requestValidationMode="4.0"</code>.</li>
          <li><strong>CSP Policy</strong> – Add middleware:<pre class="code-block"><code>app.Use(async (ctx, next) => {
  ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'";
  await next();
});</code></pre></li>
          <li><strong>Modern Encoding Library</strong> – Use <a href="https://github.com/OWASP/HtmlSanitizer" target="_blank">HtmlSanitizer</a> before rendering any rich-text field.</li>
          <li><strong>SIEM Rule</strong> – Sentinel KQL:<br/><code>AzureDiagnostics | where Category == "ApplicationGatewayFirewallLog" and Message contains "XSS"</code></li>
          <li><strong>Unit Tests</strong> – Add Razor view tests with <code>Microsoft.Security.Application.Encoder</code> to verify output encoding.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / Apache + PHP</h4>
        <ol>
          <li><strong>ModSecurity CRS</strong> – Enable rules 941100-941180 (XSS filters).</li>
          <li><strong>Output Escaping</strong> – In Twig/Blade templates rely on <code>{{ variable }}</code> which auto-escapes; use <code>|e('js')</code> for JS context.</li>
          <li><strong>Real-Time Alerting</strong> – <code>osquery</code> pack:
            <pre class="code-block"><code>SELECT uri, user_agent FROM apache_access WHERE status = 200 AND uri LIKE '%&lt;script%'</code></pre></li>
          <li><strong>CSP Report-Only</strong> – Serve <code>Content-Security-Policy-Report-Only</code> with <code>report-uri /csp-report</code> and inspect JSON posts.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Nginx / Node.js</h4>
        <ol>
          <li><strong>Nginx WAF</strong> – Compile ModSecurity v3 with OWASP CRS. Enable rule 941100.</li>
          <li><strong>Helmet Middleware</strong> – <code>app.use(require('helmet')({ contentSecurityPolicy: { directives: { defaultSrc:["'self'"] } } }))</code></li>
          <li><strong>Template Auto-escaping</strong> – Switch from EJS to Pug/Handlebars which encode output by default.</li>
          <li><strong>Elastic SIEM Rule</strong> – <code>url.path : "*&lt;script*&gt;"</code> OR <code>query : "%3Cscript%3E"</code></li>
          <li><strong>Unit Tests</strong> – Use <code>@jest/expect</code> to assert that user input appears only under <code>textContent</code>, not <code>innerHTML</code>.</li>
        </ol>
      `
    },

    // Example for broken access control
    brokenAccessControl: {
      title: "A01:2021 - Broken Access Control",
      content: `
        <h3>Server-side Access Control Overview</h3>
        <p>
          Broken access control moves up from the fifth position to #1. The 34 CWEs mapped to Broken Access Control had more occurrences in applications than any other category.
        </p>
        <ul>
          <li>Enforce access control through a trusted server-side component</li>
          <li>Deny access by default, unless explicitly allowed</li>
          <li>Implement access control mechanisms once and re-use them throughout the application</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> These instructions are provided <em>only</em> for educational use on systems you own or have explicit written permission to test.</p>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step&nbsp;1 – Build Your Kali&nbsp;Lab</a> to create an isolated VM / container with the required tooling.</p>
        <ol start="2">
          <li><strong>Enumerate &amp; Map the Application</strong> – Launch the GUI version of <em>OWASP&nbsp;ZAP</em> and run the "Automated&nbsp;Scan". Save the sitemap and generate a context file for later brute-force testing.</li>
          <li><strong>Discover Unprotected Resources</strong> – From ZAP choose "Forced Browse", load <code>/usr/share/wordlists/dirb/common.txt</code>, and scan for hidden URLs such as <code>/admin</code>, <code>/actuator</code>, <code>/api/v1/users</code>. Flag every unexpected HTTP 200/302.</li>
          <li><strong>Horizontal Privilege Escalation</strong> – Using <em>Burp Suite Community</em> proxy, log in as a normal user, intercept a request to <code>/api/v1/users/&lt;id&gt;</code>, send to Repeater, then iterate IDs (e.g., with sequence <code>1..25</code>). Any response that exposes another user's data indicates broken object-level access control (BOLA).</li>
          <li><strong>Vertical Privilege Escalation</strong> – Add the <em>AuthMatrix</em> extension. Define roles "guest", "user", "support", "admin". Import previously captured traffic and run "Generate Matrix". Green cells outside their role indicate missing role enforcement.</li>
          <li><strong>Bypass Tricks</strong> – Attempt:
            <ul>
              <li>HTTP verb tampering (<code>DELETE</code> → <code>GET</code>, etc.)</li>
              <li>Path traversal/encoding (<code>..%2Fadmin</code>, double slashes)</li>
              <li>Header overrides (<code>X-Original-URL</code>, <code>X-Forwarded-For: '127.0.0.1'</code>)</li>
            </ul>
            Record any request that evades the control.</li>
          <li><strong>Session Fixation &amp; Prediction</strong> – With Burp Intruder, fuzz captured session cookies and monitor for collisions that return HTTP 200.</li>
          <li><strong>Reporting</strong> – For each finding include: vulnerable endpoint, crafted request (as cURL), server response, affected role, and business impact.</li>
        </ol>
        <p><em>Next Step:</em> Convert your manual tests into an <code>autorize</code> plugin policy for continuous regression testing.</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / ASP.NET Core</h4>
        <ol>
          <li><strong>Centralised Authorisation</strong> – Implement policy-based RBAC:<pre class="code-block"><code>services.AddAuthorization(o =>
{
  o.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
});
[Authorize("AdminOnly")]
public IActionResult AdminArea() => Ok();</code></pre></li>
          <li><strong>Verbose Authorisation Logging</strong> – In <code>appsettings.Production.json</code> set <code>"Microsoft.AspNetCore.Authorization": "Information"</code> and forward <code>Application</code> logs to Microsoft Sentinel.</li>
          <li><strong>Sentinel Detection Rule</strong> – KQL:<br/><code>AppTraces | where Message has "/admin" and HttpStatus == 200 and UserId != "Admin"</code></li>
          <li><strong>WAF Enforcement</strong> – Deploy Azure WAF v2 with OWASP CRS 3.3; raise anomaly threshold to 5 and enable rule 931120 (path traversal).</li>
          <li><strong>CI Tests</strong> – Add xUnit integration tests using <code>WebApplicationFactory</code> to assert every protected endpoint returns 403 for unauthenticated users.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / Apache + PHP</h4>
        <ol>
          <li><strong>Enable ModSecurity v3 + OWASP CRS</strong> – Install via Homebrew, include the CRS, and enable rules 932100-932130 for access-control bypass detection.</li>
          <li><strong>Laravel/Symfony Gates</strong> – Define central gates/policies and use middleware groups to guard every route:<pre class="code-block"><code>Gate::define('admin', fn($u) => $u->isAdmin());
Route::middleware('can:admin')->group(function(){ Route::get('/admin', ...); });</code></pre></li>
          <li><strong>Real-Time Monitoring</strong> – Use <code>osquery</code>:<pre class="code-block"><code>SELECT datetime, uri, status FROM apache_access 
WHERE status = 200 AND uri LIKE '/admin%';</code></pre>Ship results to Wazuh for alerting.</li>
          <li><strong>Audit &amp; Review</strong> – Run <code>lynis audit system --tests-from-group authentication authorization</code> weekly.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Nginx / Node.js</h4>
        <ol>
          <li><strong>Reverse-Proxy ACL</strong> – In Nginx:<pre class="code-block"><code>map $cookie_role $acl { default 0; ~*admin 1; }
location /admin {
  if ($acl = 0) { return 403; }
  proxy_pass http://backend;
}</code></pre></li>
          <li><strong>Node.js RBAC</strong> – Employ <code>casl</code> or <code>express-jwt-permissions</code> to enforce permissions in code.</li>
          <li><strong>Elastic SIEM Rule</strong> – KQL:<br/><code>url.path : "/admin*" and response.status_code == 200 and user.name != "admin"</code></li>
          <li><strong>Continuous Scans</strong> – Daily <code>nikto</code>/<code>naabu</code> scheduled via cron; alert on any new HTTP 200 for restricted paths.</li>
          <li><strong>Container Hardening</strong> – Run Node inside a non-root user container with <code>readOnlyRootFilesystem: true</code>.</li>
        </ol>
      `
    },

    commandExecution: {
      title: "A03:2021 - Command Injection",
      content: `
        <h3>Command Injection Overview</h3>
        <p>
          Command injection can allow attackers to execute arbitrary system commands on the host.
        </p>
        <ul>
          <li>Avoid command execution if possible</li>
          <li>Use safer alternatives like APIs or libraries</li>
          <li>If necessary, use strict input validation and command arrays</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for command injection vulnerabilities. Your goal is to determine if user input is being executed as system commands.</p>
        <ol>
          <li><strong>Identify Input Points:</strong> Look for places where user input is used in system commands (e.g., command line arguments, environment variables).</li>
          <li><strong>Test for Injection:</strong> Enter a command or command chaining in input fields and observe error messages or unexpected results.</li>
          <li><strong>Confirm Vulnerability:</strong> Try logic-altering payloads (e.g., <code>; ls -la</code> or <code>& whoami</code>) to see if you can execute system commands.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>Burp Suite</strong> or <strong>OWASP ZAP</strong> for automated testing.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you execute system commands? What happens if you use different payloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender for a .NET app. Your goal is to detect and prevent command injection.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all system command executions and unexpected errors. Use Windows Event Logs and your SIEM to track suspicious command activity.</li>
          <li><strong>Alert:</strong> Set up alerts for unusual command patterns, failed executions, or commands run by the web server user.</li>
          <li><strong>Investigate:</strong> Review logs for unexpected command invocations, correlate with user actions and input, and check for privilege escalation attempts.</li>
          <li><strong>Harden:</strong> Use safe APIs, restrict command execution, and implement allow-lists for commands.</li>
          <li><strong>Learning Moment:</strong> Simulate command injection in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Use Safe APIs</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Instead of Process.Start with shell
Process.Start("cmd.exe", "/c " + userInput);  // Unsafe

# Use safe alternatives
Process.Start(new ProcessStartInfo {
    FileName = "program.exe",
    Arguments = sanitizedInput,
    UseShellExecute = false,
    RedirectStandardOutput = true
});
        </code></pre>
        <h5>2. AppLocker Rules</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# PowerShell command to create AppLocker rule
New-AppLockerPolicy -RuleType Path -PathCondition "C:\\Windows\\*" -User 'Everyone' -Action 'Allow'
        </code></pre>
        <h5>3. Windows Defender Application Control</h5>
        <p>Enable and configure WDAC policies to restrict executable files.</p>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Mac app. Your goal is to detect and prevent command injection.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all system command executions and unexpected errors. Use system logs and tools like OSQuery to track suspicious command activity.</li>
          <li><strong>Alert:</strong> Set up alerts for unusual command patterns, failed executions, or commands run by the web server user.</li>
          <li><strong>Investigate:</strong> Review logs for unexpected command invocations, correlate with user actions and input, and check for privilege escalation attempts.</li>
          <li><strong>Harden:</strong> Use NSTask instead of system(), enable System Integrity Protection, and keep XProtect and Gatekeeper updated.</li>
          <li><strong>Learning Moment:</strong> Simulate command injection in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Use NSTask Instead of system()</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/bin/ls"];
[task setArguments:@[@"-l"]];
[task launch];
        </code></pre>
        <h5>2. System Integrity Protection</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Check SIP status
csrutil status

# Enable SIP (requires recovery mode)
csrutil enable
        </code></pre>
        <h5>3. XProtect and Gatekeeper</h5>
        <p>Keep XProtect and Gatekeeper enabled and updated.</p>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Linux app. Your goal is to detect and prevent command injection.</p>
        <ol>
          <li><strong>Monitor:</strong> Use auditd, OSSEC, or ELK Stack to monitor command execution and suspicious activity.</li>
          <li><strong>Alert:</strong> Set up alerts for unexpected command invocations, failed executions, or commands run by the web server user.</li>
          <li><strong>Investigate:</strong> Review logs for unexpected command invocations, correlate with user actions and input, and check for privilege escalation attempts.</li>
          <li><strong>Harden:</strong> Use safe execution methods, restrict shell access, and remove unnecessary SUID binaries.</li>
          <li><strong>Learning Moment:</strong> Simulate command injection in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Use Safe Execution Methods</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Instead of exec or system
const { execFile } = require('child_process');
execFile('ls', ['-l'], (error, stdout, stderr) => {
    if (error) {
        console.error('Error:', error);
        return;
    }
    console.log(stdout);
});
        </code></pre>
        <h5>2. SELinux/AppArmor Profiles</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# AppArmor profile
profile web-app /usr/bin/web-app {
    /usr/bin/web-app r,
    /var/www/** r,
    deny /etc/shadow r,
    deny /etc/passwd r,
}
        </code></pre>
        <h5>3. System Hardening</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Restrict shell access
chsh -s /usr/sbin/nologin username

# Remove unnecessary SUID binaries
find / -perm -4000 -type f
chmod u-s /path/to/unnecessary/suid/binary
        </code></pre>
      `
    },

    sensitiveExposure: {
      title: "A02:2021 - Cryptographic Failures",
      content: `
        <h3>Sensitive Data Exposure Overview</h3>
        <p>
          Exposing sensitive data like API keys or credentials can lead to unauthorized access and account takeover.
        </p>
        <ul>
          <li>Never hardcode sensitive data in source code</li>
          <li>Use environment variables or secure vaults</li>
          <li>Implement proper encryption for sensitive data storage</li>
          <li>Use secrets scanning tools (e.g., GitGuardian, TruffleHog) to detect accidental leaks</li>
          <li>Consider cloud KMS (Key Management Services) for managing secrets at scale</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> Conduct these tests only in a lab or with written permission.</p>
        <p>Set up your lab using <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red&nbsp;Team Step&nbsp;1</a>.</p>
        <ol start="2">
          <li><strong>Passive Recon – Network Sniffing</strong><br/>
            Start <code>wireshark</code> (GUI) or <code>tcpdump -i eth0 -w capture.pcap</code>. Browse the target app and filter traffic with <code>tcp.port==80 || tcp.port==443</code>.</li>
          <li><strong>Look for Plaintext Secrets</strong><br/>
            Use Wireshark's "Follow HTTP stream". Search for regex <code>(api|secret|token|password)=</code>. Save offending requests.</li>
          <li><strong>HTTPS Downgrade</strong><br/>
            Run <code>sslstrip -l 8080</code> and set your browser proxy to 8080. If the site loads over HTTP you've forced a downgrade.</li>
          <li><strong>Mixed-Content Injection</strong><br/>
            If the page loads scripts from <code>http://</code>, host a malicious JS file locally and ARP-spoof the victim; observe token exfiltration.</li>
          <li><strong>Cloud-Storage Exposure</strong><br/>
            Enumerate common S3 buckets with <code>aws s3 ls s3://&lt;company&gt;-{assets,static,prod}</code>. Public READ/WRITE ACLs leak data.</li>
        </ol>
        <p><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</p>
        <p><em>What to try next:</em> Can you decrypt TLS using stolen private keys? What happens if you inject a malicious service-worker?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / .NET & Azure</h4>
        <ol>
          <li><strong>Detect Weak Crypto</strong> – Enable "Schannel Event 36882" auditing to catch TLS versions &lt; 1.2.</li>
          <li><strong>Key Management</strong> – Store secrets in <code>Azure Key Vault</code>. Access via <code>DefaultAzureCredential</code>; disable <code>APPSETTINGS_*</code> plain secrets.</li>
          <li><strong>DPAPI at Rest</strong> – Wrap any on-disk secret with <code>ProtectedData.Protect()</code>.</li>
          <li><strong>Sentinel Alert</strong> – KQL:<br/><code>AzureDiagnostics | where Message has "TLS_DHE" or Message has "RC4"</code></li>
          <li><strong>Automatic Secret Scan</strong> – Integrate <code>GitHub Advanced Security</code> or <code>truffleHog</code> in Azure DevOps pipelines.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / PHP + Apache</h4>
        <ol>
          <li><strong>TLS Enforcement</strong> – In <code>httpd.conf</code> redirect all :80 requests to :443 and add <code>Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"</code>.</li>
          <li><strong>Secrets as Env Vars</strong> – Export via <code>/etc/apache2/envvars</code>; reference in PHP via <code>$_ENV['DB_PASS']</code>.</li>
          <li><strong>Scan for Leaks</strong> – Run <code>ggshield scan repo .</code> weekly via cron; email results.</li>
          <li><strong>ModSecurity Rule</strong> – Block accidental key leaks: <code>SecRule RESPONSE_BODY "(?i)(api|secret|token|password)=.{10,}" "id:950013,phase:4,block,msg:'Possible secret leak'"</code></li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Docker / Node</h4>
        <ol>
          <li><strong>TLS-only Ingress</strong> – Terminate TLS at Nginx with <code>ssl_protocols TLSv1.2 TLSv1.3;</code> and <code>ssl_ciphers 'EECDH+AESGCM'</code>.</li>
          <li><strong>Kubernetes Secret</strong> – Mount secrets via <code>envFrom: secretRef</code>; ensure <code>fsGroup</code> is non-root.</li>
          <li><strong>Runtime Scan</strong> – Deploy <code>trivy fs /app</code> in CI; fail build if HIGH vulns > 0.</li>
          <li><strong>Elastic Alert</strong> – Watch for <code>"POST /login HTTP/1.1" 200</code> over plaintext port 80.</li>
          <li><strong>openssl Config</strong> – Disable legacy provider and weak ciphers in <code>/etc/ssl/openssl.cnf</code>.</li>
        </ol>
      `
    },

    xxeVulnerability: {
      title: "A05:2021 - XML External Entity (XXE)",
      content: `
        <h3>XXE Attack Overview</h3>
        <p>
          XXE vulnerabilities can lead to data disclosure, denial of service, and server-side request forgery.
        </p>
        <ul>
          <li>Disable XML external entity processing</li>
          <li>Use safe XML parsers and configurations</li>
          <li>Validate and sanitize XML input</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for XXE vulnerabilities. Your goal is to determine if external entities are being processed in XML input.</p>
        <ol>
          <li><strong>Identify XML Input Points:</strong> Look for places where XML input is processed (e.g., XML parsing, API endpoints).</li>
          <li><strong>Test for XXE:</strong> Enter an external entity payload in XML input fields and observe error messages or unexpected results.</li>
          <li><strong>Confirm Vulnerability:</strong> Verify if the external entity is being processed.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>XXEinjector</strong> for automated testing.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you extract sensitive data? What happens if you use different payloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender for a .NET app. Your goal is to detect and prevent XXE (XML External Entity) attacks.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all XML parsing errors and unexpected external requests. Use Windows Event Logs and your SIEM to track XML parsing activity.</li>
          <li><strong>Alert:</strong> Set up alerts for XML parsing errors, external entity references, or unexpected outbound requests from the app server.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious XML input, failed parsing, or external requests. Correlate with user actions and input sources.</li>
          <li><strong>Harden:</strong> Disable DTD processing, use safe XML parsers, and validate all XML input (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate XXE payloads in a test app and see if your monitoring catches them.</li>
        </ol>
        <h5>1. Safe XML Parsing</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Disable DTD processing
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};

using (XmlReader reader = XmlReader.Create(stream, settings)) {
    # Parse XML safely
}
        </code></pre>
        <h5>2. Web.config Security</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<configuration>
  <system.xml.serialization>
    <xmlSerializer checkDeserialize="true" />
  </system.xml.serialization>
</configuration>
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/PHP)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP app on Mac. Your goal is to detect and prevent XXE attacks.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all XML parsing errors and unexpected external requests. Use system logs and tools like OSSEC to track XML parsing activity.</li>
          <li><strong>Alert:</strong> Set up alerts for XML parsing errors, external entity references, or unexpected outbound requests from the app server.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious XML input, failed parsing, or external requests. Correlate with user actions and input sources.</li>
          <li><strong>Harden:</strong> Disable external entities, use safe XML parsing options, and validate all XML input (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate XXE payloads in a test app and see if your monitoring catches them.</li>
        </ol>
        <h5>1. libxml Security</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Disable external entities
libxml_disable_entity_loader(true);

# Safe XML parsing
$xml = simplexml_load_string($xmlstr, 'SimpleXMLElement', 
    LIBXML_NOENT | LIBXML_NOCDATA);
        </code></pre>
        <h5>2. PHP Configuration</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# php.ini settings
libxml.disable_entity_loader = 'On'
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux/Node.js)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Node.js app on Linux. Your goal is to detect and prevent XXE attacks.</p>
        <ol>
          <li><strong>Monitor:</strong> Use auditd, OSSEC, or ELK Stack to monitor XML parsing errors and unexpected external requests.</li>
          <li><strong>Alert:</strong> Set up alerts for XML parsing errors, external entity references, or unexpected outbound requests from the app server.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious XML input, failed parsing, or external requests. Correlate with user actions and input sources.</li>
          <li><strong>Harden:</strong> Use safe XML parser configs, disable external entities, and validate all XML input (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate XXE payloads in a test app and see if your monitoring catches them.</li>
        </ol>
        <h5>1. XML Parser Configuration</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using xml2js safely
const parser = new xml2js.Parser({
  explicitEntities: false,
  resolveEntities: false
});

parser.parseString(xml, (err, result) => {
  # Handle parsed XML
});
        </code></pre>
        <h5>2. ModSecurity Rules</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Detect XXE attempts
SecRule REQUEST_BODY "@contains <!ENTITY" \
  "id:1000,phase:2,deny,status:403,msg:'XXE Attack Detected'"
        </code></pre>
      `
    },

    securityMisconfig: {
      title: "A05:2021 - Security Misconfiguration",
      content: `
        <h3>Security Misconfiguration Overview</h3>
        <p>
          Security misconfiguration happens when security settings are defined, implemented, or maintained using insecure values. This is one of the most common vulnerabilities.
        </p>
        <ul>
          <li>Use secure default configurations</li>
          <li>Remove unused features and frameworks</li>
          <li>Keep all systems and dependencies up to date</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> Only test systems you own or have explicit permission to test.</p>
        <p>Begin with <a href="/guides/red-team-step-1.html" target="_blank">Red Team Step&nbsp;1 – Build Your Kali&nbsp;Lab</a>.</p>
        <ol start="2">
          <li><strong>Fingerprint Services</strong> – Run <code>nmap -sV -p- target</code>. Note out-of-date versions, unintended open ports, test/ staging subdomains.</li>
          <li><strong>Scan Common Misconfigs</strong> – Use <code>nikto -h https://target</code> and <code>wpscan</code> / <code>joomscan</code> for framework defaults.</li>
          <li><strong>Security Headers</strong> – In <em>OWASP ZAP</em> "Passive Scan" look for missing <code>CSP</code>, <code>X-Frame-Options</code>, <code>HSTS</code>.</li>
          <li><strong>CORS Misconfig</strong> – Send origin <code>https://evil.com</code> in Burp Repeater and check <code>Access-Control-Allow-Origin: *</code> or reflection.</li>
          <li><strong>Directory Listing / Backup Files</strong> – Use <code>ffuf -c -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt</code>. Look for <code>.git/</code>, <code>.env</code>, <code>wp-config.php~</code>.</li>
          <li><strong>Cloud Metadata Exposure</strong> – Curl <code>http://169.254.169.254/latest/meta-data/</code> via SSRF vectors.</li>
        </ol>
        <p><strong>Learning Moment:</strong> Spin up OWASP <a href="https://github.com/OWASP/railsgoat" target="_blank">RailsGoat</a> or Juice Shop and harden headers—re-scan to verify.</p>
        <p><em>What to try next:</em> Can you poison DNS via misconfigured <code>/etc/hosts</code>? Can you upload a <code>.php</code> shell to a mis-configured S3 bucket?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / IIS</h4>
        <ol>
          <li><strong>Baseline with IIS Crypto</strong> – Disable SSLv3 / TLS&nbsp;1.0 and weak ciphers.</li>
          <li><strong>Auto-Hardening</strong> – Apply <a href="https://learn.microsoft.com/iis/manage/configuring-security/url-scan" target="_blank">URLScan</a> 3.1; block <code>TRACE</code>, <code>WEBDAV</code>.</li>
          <li><strong>Config Drift Detection</strong> – Enable <code>AppLocker</code> and monitor <code>Microsoft-Windows-IIS-Configuration/Operational</code> logs.</li>
          <li><strong>Azure WAF Policy</strong> – OWASP CRS 3.3, anomaly threshold 5; enable rule 942100 (strict transport) & 941100 (XSS).</li>
          <li><strong>CIS Benchmark</strong> – Run <code>CIS-CAT</code> against Windows 2019; remediate High findings.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / Apache + PHP</h4>
        <ol>
          <li><strong>Disable Modules</strong> – Comment out unused modules in <code>httpd.conf</code> (<code>'cgi'</code>, <code>'status'</code>, <code>'info'</code>).</li>
          <li><strong>Secure Defaults</strong> – <code>Options '-Indexes'</code>, <code>ServerTokens 'Prod'</code>, <code>ServerSignature 'Off'</code>.</li>
          <li><strong>mod_security CRS</strong> – Enable rules 930100-931000 (protocol violations).</li>
          <li><strong>Automated Audit</strong> – <code>lynis audit system --tests-from-group apache,php</code>; fix score &lt; 80.</li>
          <li><strong>Log Rotation &amp; Monitoring</strong> – Use <code>fail2ban</code> jail <code>apache-badbots</code> and ship logs to Wazuh.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Nginx & Docker</h4>
        <ol>
          <li><strong>Nginx Hardening</strong> – <code>server_tokens off;</code> <code>add_header X-Content-Type-Options nosniff;</code> limit body to 1 MB.</li>
          <li><strong>Container Benchmarks</strong> – Run <code>docker bench security</code> and <code>kube-bench</code>; enforce read-only root FS.</li>
          <li><strong>Infrastructure as Code Scans</strong> – Use <code>tfsec</code> / <code>checkov</code> on Terraform/K8s manifests.</li>
          <li><strong>Automated Header Tests</strong> – GitHub Action executes <code>zap-baseline.py -t $URL</code> on every PR.</li>
          <li><strong>Periodic CIS Scan</strong> – <code>lynis audit system --cronjob</code>; email report diff.</li>
        </ol>
      `
    },

    insecureDeserialization: {
      title: "A08:2021 - Software and Data Integrity Failures",
      content: `
        <h3>Insecure Deserialization Overview</h3>
        <p>
          Insecure deserialization can lead to remote code execution or privilege escalation if untrusted input is deserialized.
        </p>
        <ul>
          <li>Use digital signatures to verify integrity</li>
          <li>Use safe deserializers</li>
          <li>Validate all serialized data from untrusted sources</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for insecure deserialization vulnerabilities. Your goal is to determine if untrusted input is being deserialized.</p>
        <ol>
          <li><strong>Identify Deserialization Points:</strong> Look for places where serialized data is being processed (e.g., API endpoints, file uploads).</li>
          <li><strong>Test for Deserialization:</strong> Enter a serialized payload in input fields and observe error messages or unexpected results.</li>
          <li><strong>Confirm Vulnerability:</strong> Verify if the serialized data is being executed.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>ysoserial</strong> for automated testing.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you execute code? What happens if you use different payloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender for a .NET app. Your goal is to detect and prevent insecure deserialization attacks.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all deserialization errors, unexpected object types, and failed input validation. Use Windows Event Logs and your SIEM to track deserialization activity.</li>
          <li><strong>Alert:</strong> Set up alerts for deserialization errors, use of unsafe deserializers, or unexpected object types.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious deserialization activity, correlate with user actions and input sources.</li>
          <li><strong>Harden:</strong> Use safe deserializers, validate all input, and avoid deserializing untrusted data (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate deserialization attacks in a test app and see if your monitoring catches them.</li>
        </ol>
        <h5>1. Safe Deserialization</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Use JSON instead of BinaryFormatter
var options = new JsonSerializerOptions
{
    TypeInfoResolver = JsonSerializer.IsReflectionEnabledByDefault
};

var obj = JsonSerializer.Deserialize<SafeType>(json, options);
        </code></pre>
        <h5>2. Input Validation</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Validate before deserializing
if (!IsValidInput(input))
{
    throw new SecurityException("Invalid input");
}

[JsonSerializable(typeof(SafeType))]
public partial class JsonContext : JsonSerializerContext
{
}
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/PHP)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP app on Mac. Your goal is to detect and prevent insecure deserialization attacks.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all deserialization errors, unexpected object types, and failed input validation. Use system logs and tools like OSSEC to track deserialization activity.</li>
          <li><strong>Alert:</strong> Set up alerts for deserialization errors, use of unsafe deserializers, or unexpected object types.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious deserialization activity, correlate with user actions and input sources.</li>
          <li><strong>Harden:</strong> Use safe deserializers, validate all input, and avoid deserializing untrusted data (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate deserialization attacks in a test app and see if your monitoring catches them.</li>
        </ol>
        <h5>1. Safe Deserialization in PHP</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Use JSON instead of unserialize
$data = json_decode($input, true);

# If unserialize is needed, use allowed_classes
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
        </code></pre>
        <h5>2. Input Validation</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Validate structure before processing
function validateInput($input) {
    $schema = [
        'type' => 'object',
        'properties' => [
            'name' => ['type' => 'string'],
            'id' => ['type' => 'integer']
        ]
    ];
    return Validator::validate($input, $schema);
}
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux/Node.js)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Node.js app on Linux. Your goal is to detect and prevent insecure deserialization attacks.</p>
        <ol>
          <li><strong>Monitor:</strong> Use auditd, OSSEC, or ELK Stack to monitor deserialization errors, unexpected object types, and failed input validation.</li>
          <li><strong>Alert:</strong> Set up alerts for deserialization errors, use of unsafe deserializers, or unexpected object types.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious deserialization activity, correlate with user actions and input sources.</li>
          <li><strong>Harden:</strong> Use safe deserialization practices, validate all input, and avoid deserializing untrusted data (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate deserialization attacks in a test app and see if your monitoring catches them.</li>
        </ol>
        <h5>1. Safe Deserialization Practices</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Use JSON.parse instead of eval
const safeData = JSON.parse(input);

# If using node-serialize, implement whitelist
const serialize = require('node-serialize');
const whitelist = ['SafeClass'];

function safeDeserialize(input) {
    const parsed = serialize.unserialize(input);
    if (!whitelist.includes(parsed.constructor.name)) {
        throw new Error('Unsafe deserialization attempted');
    }
    return parsed;
}
        </code></pre>
        <h5>2. Security Headers and Configurations</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Express security middleware
const helmet = require('helmet');
app.use(helmet());

# Custom deserialization middleware
app.use((req, res, next) => {
    if (req.body && typeof req.body === 'string') {
        try {
            req.body = JSON.parse(req.body);
        } catch (e) {
            return res.status(400).send('Invalid JSON');
        }
    }
    next();
});
        </code></pre>
      `
    },
    insecureSubmission: {
      title: "A02:2021 - Insecure Submission (Cleartext Transmission)",
      content: `
        <h3>Insecure Submission Overview</h3>
        <p>
          Submitting sensitive data over HTTP exposes it to interception and tampering by attackers.
        </p>
        <ul>
          <li>Always use HTTPS for all data submissions</li>
          <li>Implement HSTS headers to enforce HTTPS</li>
          <li>Educate users to look for secure connections</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for insecure data submission. Your goal is to determine if sensitive data is sent over HTTP.</p>
        <ol>
          <li><strong>Identify Submission Points:</strong> Look for forms or API calls that use HTTP instead of HTTPS.</li>
          <li><strong>Test for Interception:</strong> Use a proxy (e.g., Burp Suite) to intercept traffic and check for cleartext data.</li>
          <li><strong>Confirm Vulnerability:</strong> Verify if credentials or sensitive data are visible in network traffic.</li>
          <li><strong>Automate Testing:</strong> Use tools like SSL Labs or testssl.sh to check for HTTPS enforcement.</li>
          <li><strong>Learning Moment:</strong> Try submitting a form over HTTP and see if you can intercept the data.</li>
        </ol>
      `,
      blueTeam: `
        <h4>Blue Team Walkthrough</h4>
        <p><strong>Scenario:</strong> You are a defender for a web app. Your goal is to detect and prevent insecure data submission.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all HTTP requests to sensitive endpoints. Use web server logs and SIEM tools.</li>
          <li><strong>Alert:</strong> Set up alerts for HTTP requests to login or sensitive pages.</li>
          <li><strong>Investigate:</strong> Review logs for repeated HTTP access to sensitive endpoints.</li>
          <li><strong>Harden:</strong> Redirect all HTTP traffic to HTTPS, set HSTS headers, and disable HTTP where possible.</li>
          <li><strong>Learning Moment:</strong> Simulate HTTP submissions and verify your monitoring catches them.</li>
        </ol>
        <h5>1. Enforce HTTPS</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Example Nginx redirect
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
        </code></pre>
        <h5>2. HSTS Header</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        </code></pre>
      `
    },
    securityLogging: {
      title: "A09:2021 - Security Logging and Monitoring Failures",
      content: `
        <h3>Security Logging and Monitoring Overview</h3>
        <p>
          Insufficient logging and monitoring can prevent detection of breaches and hinder incident response.
        </p>
        <ul>
          <li>Log all authentication, access control, and input validation failures</li>
          <li>Use centralized log management and monitoring</li>
          <li>Protect logs from tampering and ensure proper retention</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for logging failures. Your goal is to determine if attacks are logged and monitored.</p>
        <ol>
          <li><strong>Trigger Events:</strong> Attempt failed logins, access control violations, and input validation errors.</li>
          <li><strong>Check Logs:</strong> Review application and server logs to see if events are recorded.</li>
          <li><strong>Confirm Gaps:</strong> Identify missing or incomplete log entries for security events.</li>
          <li><strong>Automate Testing:</strong> Use log analysis tools to scan for missing events.</li>
          <li><strong>Learning Moment:</strong> Try simulating attacks and see if your actions are logged and alerted on.</li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender for a .NET or Windows app. Your goal is to ensure all critical events are logged and monitored.</p>
        <ol>
          <li><strong>Monitor:</strong> Use Windows Event Logs and a SIEM (e.g., Splunk, Sentinel) to collect logs from all systems.</li>
          <li><strong>Alert:</strong> Set up alerts for failed logins, access control violations, and suspicious activity using Windows Event Forwarding or SIEM rules.</li>
          <li><strong>Investigate:</strong> Review logs for patterns of attack or unusual activity, such as repeated failed logins or privilege escalation attempts.</li>
          <li><strong>Harden:</strong> Ensure logs are protected with NTFS permissions, enable log retention policies, and use write-once storage if possible.</li>
          <li><strong>Learning Moment:</strong> Simulate attacks and verify your monitoring and alerting works.</li>
        </ol>
        <h5>1. Enable Audit Policies</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Enable auditing for logon events
AuditPol /set /subcategory:"Logon" /failure:enable /success:enable
        </code></pre>
        <h5>2. Forward Logs to SIEM</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Use Windows Event Forwarding or an agent (e.g., Splunk Universal Forwarder)
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Mac app. Your goal is to ensure all critical events are logged and monitored.</p>
        <ol>
          <li><strong>Monitor:</strong> Use the macOS Unified Logging System (log command) and syslog for application and system logs.</li>
          <li><strong>Alert:</strong> Set up scripts or monitoring tools (e.g., osquery, Splunk) to alert on failed logins, sudo attempts, and suspicious activity.</li>
          <li><strong>Investigate:</strong> Review logs for repeated failed logins, privilege escalation, or unusual process activity.</li>
          <li><strong>Harden:</strong> Protect log files with proper permissions and use log rotation (newsyslog) to retain logs.</li>
          <li><strong>Learning Moment:</strong> Simulate attacks and verify your monitoring and alerting works.</li>
        </ol>
        <h5>1. View System Logs</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
log show --predicate 'eventMessage contains "login"' --info
        </code></pre>
        <h5>2. Log Rotation</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# /etc/newsyslog.conf controls log rotation
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Linux app. Your goal is to ensure all critical events are logged and monitored.</p>
        <ol>
          <li><strong>Monitor:</strong> Use syslog, journald, or rsyslog to collect logs from all systems and applications.</li>
          <li><strong>Alert:</strong> Set up log monitoring tools (e.g., ELK Stack, Graylog, OSSEC) to alert on failed logins, sudo attempts, and suspicious activity.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized access, plaintext secrets, or use of weak crypto. Correlate with user actions and privilege levels.</li>
          <li><strong>Harden:</strong> Use environment variables for secrets, enforce strong encryption, and scan for hardcoded secrets in code repos.</li>
          <li><strong>Learning Moment:</strong> Simulate a secrets scan and see what your monitoring tools catch.</li>
        </ol>
        <h5>1. View Auth Logs</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
tail -f /var/log/auth.log
        </code></pre>
        <h5>2. Log Rotation</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# /etc/logrotate.conf controls log rotation
        </code></pre>
      `
    },
    insecureDesign: {
      title: "A04:2021 – Insecure Design",
      content: `
        <h3>Insecure Design Overview</h3>
        <p>Insecure design covers missing or ineffective security controls at the architecture or design phase. Unlike implementation bugs, these flaws are baked into the blueprint of the application.</p>
        <ul>
          <li>Threat-model early and continuously</li>
          <li>Enforce secure development lifecycle (SDL) checkpoints</li>
          <li>Document and test security requirements just like functional ones</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> These tests assess systemic design weaknesses—perform them only on systems you own or have written permission to test.</p>
        <ol>
          <li><strong>Abuse-Case Brainstorm</strong> – Create a mind-map of "could a user…?" questions (e.g., "resize any image to 10 GB?", "submit 10 k API calls/s?"). List high-impact scenarios.</li>
          <li><strong>Business Logic Testing</strong> – Using <em>Burp Suite</em> <code>Turbo Intruder</code>, script a purchase flow where you change the price client-side to <code>$0.01</code> before checkout. Observe if the server validates.</li>
          <li><strong>Race Conditions</strong> – Launch <code>clusterbomb</code> attack sending two identical fund-transfer requests with the same nonce. If both succeed, design lacks idempotency controls.</li>
          <li><strong>Resource Exhaustion</strong> – With <code>hey</code> or <code>wrk</code> send 5k RPS to an expensive PDF-generation endpoint. Monitor response for 500 errors or OOM-kills.</li>
          <li><strong>Privilege Workflow Bypass</strong> – Manually craft a request omitting a required approval step (e.g., submit <code>/api/v1/withdraw</code> without the usual <code>/review</code>). If accepted, the workflow is insecurely designed.</li>
        </ol>
        <p><strong>Learning Moment:</strong> Run these scenarios against <a href="https://owasp.org/www-project-juice-shop/" target="_blank">Juice Shop</a> (logic flaws galore) or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</p>
        <p><em>What to try next:</em> Can you replay the same CSRF token twice? Can you freeze account balances via integer overflows?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / .NET Architecture</h4>
        <ol>
          <li><strong>Threat-Model Workshops</strong> – Use <a href="https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling" target="_blank">MS Threat Modeling Tool</a> each sprint; export STRIDE diagrams.</li>
          <li><strong>Enforce Domain-Driven Access</strong> – Implement MediatR + policy handlers; every command/query passes centralized authorization.</li>
          <li><strong>Use Integration Tests</strong> – <code>WebApplicationFactory</code> tests that purchasing workflow rejects client-side price tampering.</li>
          <li><strong>Idempotency Keys</strong> – Middleware adds <code>Idempotency-Key</code>; reject duplicate POSTs.</li>
          <li><strong>Chaos Engineering</strong> – Run <a href="https://github.com/Polly-Contrib/Simmy" target="_blank">Simmy</a> to inject latency/ faults; verify system degrades gracefully.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / Laravel</h4>
        <ol>
          <li><strong>Define Security User-Stories</strong> – e.g., "As finance admin I can refund only once." Add them to <code>tests/Feature</code>.</li>
          <li><strong>Rate-Limit Expensive Endpoints</strong> – <code>Route::post('/pdf')->middleware('throttle:10,1');</code></li>
          <li><strong>Use Transactions</strong> – Wrap money-movement logic in <code>DB::transaction()</code> to avoid partial state.</li>
          <li><strong>CSRF Double-Submit</strong> – Enable <code>VerifyCsrfToken</code> and check <code>sameSite=strict</code> cookies.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Node.js & Kubernetes</h4>
        <ol>
          <li><strong>Pod Security</strong> – Set <code>cpu/memory limits</code>; stop resource-exhaustion attacks.</li>
          <li><strong>OpenTelemetry SLOs</strong> – Alert when 95-percentile latency > baseline → potential logic-loop abuse.</li>
          <li><strong>Central Workflow Engine</strong> – Offload approvals to Camunda/Temporal so every step is audited/versioned.</li>
          <li><strong>Use Feature Flags</strong> – Roll out risky logic behind flags and monitor.</li>
        </ol>
      `
    },
    vulnerableComponents: {
      title: "A06:2021 – Vulnerable & Outdated Components",
      content: `
        <h3>Vulnerable and Outdated Components Overview</h3>
        <p>Using dependencies with known CVEs or outdated versions can introduce exploitable flaws in your application.</p>
        <ul>
          <li>Inventory versions of all third-party libraries, containers, and OS packages</li>
          <li>Subscribe to vulnerability feeds (NVD, GitHub Advisories, OSV)</li>
          <li>Automate SCA (Software Composition Analysis) in CI/CD</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p><strong>Read this first:</strong> Only test on systems you own or have written permission to test.</p>
        <ol>
          <li><strong>Enumerate Packages</strong> – For Node.js run <code>npm list --depth 2</code>; for Python <code>pip list --outdated</code>; for Docker <code>trivy fs .</code>.</li>
          <li><strong>Check CVEs</strong> – Use <code>nvd.nist.gov</code> or the CLI <code>osv-scanner --lockfile=package-lock.json</code>. Identify high/critical scores.</li>
          <li><strong>Exploit Public PoCs</strong> – Search <code>exploit-db</code> for version-specific exploits (e.g., Log4Shell 2.14.1). Spin up vulnerable container; validate RCE.</li>
          <li><strong>Dependency Confusion</strong> – Create a package name that matches an internal one (e.g., <code>acme-utils</code>) and upload to public registry if not claimed.</li>
          <li><strong>Typosquatting</strong> – Register <code>lodashs</code> or similar and see if CI pulls it.</li>
        </ol>
        <p><strong>Learning Moment:</strong> Fork Juice Shop, downgrade <code>express</code> to 4.16.0, and exploit CVE-2018-11655 path traversal.</p>
        <p><em>What to try next:</em> Can you hijack a supply-chain by poisoning an S3 bucket used for installer downloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / .NET & NuGet</h4>
        <ol>
          <li><strong>SCA in Pipeline</strong> – Add <code>dotnet list package --vulnerable</code> gate; fail build on HIGH.</li>
          <li><strong>Dependabot</strong> – Enable weekly security PRs for NuGet packages.</li>
          <li><strong>Runtime Guard</strong> – Enable <code>AssemblyLoadContext.Resolving</code> callback; block unsigned DLLs.</li>
          <li><strong>Windows Defender Exploit Guard</strong> – Turn on <code>ExploitProtection</code> profiles for known component exploits.</li>
        </ol>
      `,
      blueTeamMac: `
        <h4>Blue Team Playbook – macOS / Homebrew & PHP Composer</h4>
        <ol>
          <li><strong>Composer Audit</strong> – <code>composer audit --format=json</code> in CI; break build on critical CVSS &gt;=9.</li>
          <li><strong>Brew Bundle</strong> – Pin versions via <code>Brewfile.lock.json</code>; run <code>brew bundle check</code>.</li>
          <li><strong>SBOM Generation</strong> – Use <code>syft packages dir:</code> to create CycloneDX SBOM.</li>
          <li><strong>Lockfile Integrity</strong> – Commit <code>composer.lock</code>; enable GitHub <code>push --force-with-lease</code> policy to avoid tampering.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Docker & Node</h4>
        <ol>
          <li><strong>Trivy in CI</strong> – <code>trivy image --severity HIGH,CRITICAL myapp:latest</code>.</li>
          <li><strong>Snyk Monitor</strong> – <code>snyk monitor --org=myteam</code>; receive email alerts on new CVEs.</li>
          <li><strong>Base-Image Hygiene</strong> – Use <code>FROM node:18-slim</code> not <code>'latest'</code>. Apply weekly rebuilds.</li>
          <li><strong>Readonly Root FS</strong> – In Kubernetes set <code>readOnlyRootFilesystem: true</code> to limit malicious package writes.</li>
          <li><strong>CVE Patch Window</strong> – Policy: deploy patch within 7 days (critical) / 30 days (high).</li>
        </ol>
      `
    },

    // Add missing vulnerability guides
    hardcodedSecret: {
      title: "A02:2021 - Hardcoded Credentials",
      content: `
        <h3>Hardcoded Credentials Overview</h3>
        <p>
          Hardcoded credentials in source code can be discovered by attackers, providing direct access to systems and data.
        </p>
        <ul>
          <li>Never store secrets directly in source code</li>
          <li>Use environment variables or secure vaults</li>
          <li>Implement proper secrets management</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step 1 – Build Your Kali Lab</a> to create an isolated VM / container with the required tooling.</p>
        <p><strong>Read this first:</strong> These instructions are provided <em>only</em> for educational use on systems you own or have explicit written permission to test.</p>
        <ol>
          <li><strong>Source Code Review</strong> – Search for patterns like <code>password=</code>, <code>api_key=</code>, <code>secret=</code> in repos</li>
          <li><strong>Git History Mining</strong> – Use <code>git log --grep="password\\|key\\|secret" -p</code> to find secrets in commit history</li>
          <li><strong>Automated Scanning</strong> – Run <code>truffleHog</code> or <code>gitleaks</code> against target repositories</li>
          <li><strong>Config File Analysis</strong> – Check <code>.env</code>, <code>config.js</code>, <code>settings.py</code> files</li>
          <li><strong>Binary Analysis</strong> – Use <code>strings</code> command on compiled binaries to extract hardcoded secrets</li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows</h4>
        <ol>
          <li><strong>Azure Key Vault</strong> – Store secrets in Azure Key Vault, access via managed identity</li>
          <li><strong>PowerShell SecretManagement</strong> – Use <code>Microsoft.PowerShell.SecretManagement</code> module</li>
          <li><strong>Git Hooks</strong> – Implement pre-commit hooks to scan for secrets</li>
          <li><strong>Code Scanning</strong> – Enable GitHub Advanced Security or Azure DevOps credential scanner</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux</h4>
        <ol>
          <li><strong>Environment Variables</strong> – Store secrets in <code>/etc/environment</code> or systemd service files</li>
          <li><strong>HashiCorp Vault</strong> – Deploy Vault for centralized secrets management</li>
          <li><strong>Git Hooks</strong> – Install <code>detect-secrets</code> pre-commit hook</li>
          <li><strong>Container Secrets</strong> – Use Kubernetes secrets or Docker secrets</li>
        </ol>
      `
    },

    noSqlInjection: {
      title: "A03:2021 - NoSQL Injection",
      content: `
        <h3>NoSQL Injection Overview</h3>
        <p>
          NoSQL injection occurs when untrusted data is inserted into NoSQL queries without proper validation.
        </p>
        <ul>
          <li>Use parameterized queries</li>
          <li>Validate and sanitize all input</li>
          <li>Implement proper access controls</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step 1 – Build Your Kali Lab</a> to create an isolated VM / container with the required tooling.</p>
        <p><strong>Read this first:</strong> Only test systems you own or have explicit permission to test.</p>
        <ol>
          <li><strong>Input Discovery</strong> – Find NoSQL query parameters in web apps (MongoDB, CouchDB, etc.)</li>
          <li><strong>Boolean Injection</strong> – Try payloads like <code>{"$ne": null}</code> to bypass authentication</li>
          <li><strong>JavaScript Injection</strong> – Test <code>$where</code> clauses with malicious JavaScript</li>
          <li><strong>Operator Injection</strong> – Use MongoDB operators like <code>$regex</code>, <code>$gt</code>, <code>$lt</code></li>
          <li><strong>Data Extraction</strong> – Use <code>$regex</code> for blind data extraction character by character</li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows / .NET</h4>
        <ol>
          <li><strong>Use Official Drivers</strong> – Use MongoDB.Driver with parameterized queries</li>
          <li><strong>Input Validation</strong> – Validate all inputs with data annotations</li>
          <li><strong>Query Logging</strong> – Enable MongoDB profiling and log slow queries</li>
          <li><strong>Network Security</strong> – Restrict database access to application servers only</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux / Node.js</h4>
        <ol>
          <li><strong>Mongoose Schemas</strong> – Use strict schemas to validate input types</li>
          <li><strong>Query Sanitization</strong> – Use <code>express-mongo-sanitize</code> middleware</li>
          <li><strong>Authentication</strong> – Enable MongoDB authentication and use minimal privileges</li>
          <li><strong>Rate Limiting</strong> – Implement query rate limiting to prevent enumeration</li>
        </ol>
      `
    },

    weakCrypto: {
      title: "A02:2021 - Weak Cryptography",
      content: `
        <h3>Weak Cryptography Overview</h3>
        <p>
          Using weak or deprecated cryptographic algorithms can expose sensitive data to attacks.
        </p>
        <ul>
          <li>Use strong, modern algorithms (AES-256, SHA-256)</li>
          <li>Avoid deprecated algorithms (MD5, SHA-1, DES)</li>
          <li>Keep cryptographic libraries updated</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step 1 – Build Your Kali Lab</a> to create an isolated VM / container with the required tooling.</p>
        <p><strong>Educational purposes only.</strong></p>
        <ol>
          <li><strong>Algorithm Detection</strong> – Identify weak crypto algorithms in use</li>
          <li><strong>Rainbow Tables</strong> – Use precomputed tables to crack MD5/SHA-1 hashes</li>
          <li><strong>Hash Collision</strong> – Exploit MD5/SHA-1 collision vulnerabilities</li>
          <li><strong>Brute Force</strong> – Use tools like <code>hashcat</code> to crack weak hashes</li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows</h4>
        <ol>
          <li><strong>Use .NET Crypto</strong> – Use <code>System.Security.Cryptography</code> with modern algorithms</li>
          <li><strong>Algorithm Policy</strong> – Disable weak algorithms via Group Policy</li>
          <li><strong>Certificate Management</strong> – Use strong certificates with SHA-256 signatures</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux</h4>
        <ol>
          <li><strong>OpenSSL Config</strong> – Configure OpenSSL to disable weak ciphers</li>
          <li><strong>TLS Settings</strong> – Use TLS 1.2+ with strong cipher suites</li>
          <li><strong>Password Hashing</strong> – Use bcrypt, scrypt, or Argon2 for passwords</li>
        </ol>
      `
    },

    pathTraversal: {
      title: "A01:2021 - Path Traversal", 
      content: `
        <h3>Path Traversal Overview</h3>
        <p>
          Path traversal attacks allow attackers to access files outside the intended directory structure.
        </p>
        <ul>
          <li>Validate and sanitize file paths</li>
          <li>Use whitelists for allowed files</li>
          <li>Implement proper access controls</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step 1 – Build Your Kali Lab</a> to create an isolated VM / container with the required tooling.</p>
        <p><strong>Educational purposes only.</strong></p>
        <ol>
          <li><strong>Basic Traversal</strong> – Try <code>../../../etc/passwd</code> in file parameters</li>
          <li><strong>Encoding Bypass</strong> – Use URL encoding <code>%2e%2e%2f</code> or double encoding</li>
          <li><strong>Null Byte Injection</strong> – Append <code>%00</code> to bypass file extension checks</li>
          <li><strong>Windows Paths</strong> – Test <code>..\\..\\windows\\system32\\drivers\\etc\\hosts</code></li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows</h4>
        <ol>
          <li><strong>Path Validation</strong> – Use <code>Path.GetFullPath()</code> and validate against allowed directories</li>
          <li><strong>File System ACLs</strong> – Set restrictive NTFS permissions</li>
          <li><strong>Code Access Security</strong> – Use <code>FileIOPermission</code> to restrict file access</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux</h4>
        <ol>
          <li><strong>Path Sanitization</strong> – Use <code>path.resolve()</code> and validate against chroot</li>
          <li><strong>File Permissions</strong> – Set restrictive file permissions (chmod 644/755)</li>
          <li><strong>Chroot Jail</strong> – Run applications in chroot environment</li>
        </ol>
      `
    },

    openRedirect: {
      title: "A01:2021 - Open Redirect",
      content: `
        <h3>Open Redirect Overview</h3>
        <p>
          Open redirects can be used in phishing attacks to redirect users to malicious websites.
        </p>
        <ul>
          <li>Validate redirect URLs against whitelists</li>
          <li>Use relative URLs when possible</li>
          <li>Implement proper URL validation</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step 1 – Build Your Kali Lab</a> to create an isolated VM / container with the required tooling.</p>
        <p><strong>Educational purposes only.</strong></p>
        <ol>
          <li><strong>Parameter Discovery</strong> – Find redirect parameters like <code>?redirect=</code>, <code>?url=</code></li>
          <li><strong>Direct Redirect</strong> – Test <code>?redirect=https://evil.com</code></li>
          <li><strong>Protocol Bypass</strong> – Try <code>//evil.com</code> (protocol-relative URL)</li>
          <li><strong>Encoding Bypass</strong> – Use URL encoding to bypass filters</li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows</h4>
        <ol>
          <li><strong>URL Validation</strong> – Use <code>Uri.IsWellFormedUriString()</code> with validation</li>
          <li><strong>Whitelist Domains</strong> – Maintain allowed redirect domains list</li>
          <li><strong>Relative URLs</strong> – Prefer relative redirects over absolute ones</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux</h4>
        <ol>
          <li><strong>URL Parsing</strong> – Use proper URL parsing libraries</li>
          <li><strong>Domain Validation</strong> – Check hostname against allowed domains</li>
          <li><strong>HTTP Headers</strong> – Set <code>Referrer-Policy</code> headers</li>
        </ol>
      `
    },

    ssrf: {
      title: "A10:2021 - Server-Side Request Forgery",
      content: `
        <h3>SSRF Overview</h3>
        <p>
          SSRF allows attackers to make requests from your server to internal or external systems.
        </p>
        <ul>
          <li>Validate and whitelist allowed URLs</li>
          <li>Implement network segmentation</li>
          <li>Use deny lists for private IP ranges</li>
        </ul>
      `,
      redTeam: `
        <h4>Red Team Walkthrough</h4>
        <p>Start with <a href="/guides/red-team-step-1.html" target="_blank" rel="noopener noreferrer">Red Team Step 1 – Build Your Kali Lab</a> to create an isolated VM / container with the required tooling.</p>
        <p><strong>Educational purposes only.</strong></p>
        <ol>
          <li><strong>Internal Service Discovery</strong> – Try accessing <code>http://127.0.0.1:8080</code>, <code>http://localhost:3000</code></li>
          <li><strong>Cloud Metadata</strong> – Access <code>http://169.254.169.254/latest/meta-data/</code> (AWS)</li>
          <li><strong>Port Scanning</strong> – Use SSRF to scan internal network ports</li>
          <li><strong>Protocol Bypass</strong> – Try <code>file://</code>, <code>gopher://</code>, <code>dict://</code> protocols</li>
        </ol>
      `,
      blueTeamWindows: `
        <h4>Blue Team Playbook – Windows</h4>
        <ol>
          <li><strong>URL Filtering</strong> – Block private IP ranges (RFC 1918)</li>
          <li><strong>Network Segmentation</strong> – Isolate web servers from internal services</li>
          <li><strong>Proxy Configuration</strong> – Use explicit proxy with filtering rules</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Playbook – Linux</h4>
        <ol>
          <li><strong>iptables Rules</strong> – Block outbound connections to private IPs</li>
          <li><strong>DNS Filtering</strong> – Use DNS resolvers that block internal domains</li>
          <li><strong>Application Firewall</strong> – Implement WAF rules to detect SSRF patterns</li>
        </ol>
      `
    },

  }
};

export default proactiveControlsData;
export const vulnerabilityGuides = proactiveControlsData.vulnerabilityGuides;
