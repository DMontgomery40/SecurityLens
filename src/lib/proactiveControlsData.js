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
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for SQL Injection vulnerabilities. Your goal is to determine if user input is being unsafely included in SQL queries.</p>
        <ol>
          <li><strong>Identify Input Points:</strong> Look for forms, URL parameters, or API endpoints that interact with the database (e.g., login, search, profile lookup).</li>
          <li><strong>Test for Injection:</strong> Enter a single quote (<code>'</code>) or SQL meta-characters (e.g., <code>OR 1=1</code>) in input fields and observe error messages or unexpected results.</li>
          <li><strong>Confirm Vulnerability:</strong> Try logic-altering payloads (e.g., <code>' OR 'a'='a</code>) to see if you can bypass authentication or extract data.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>sqlmap</strong> for deeper analysis, but always understand what the tool is doing and review its findings manually.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you extract table names or data? What happens if you use time-based payloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender responsible for a .NET web application. Your goal is to detect, prevent, and respond to SQL Injection attempts.</p>
        <ol>
          <li><strong>Monitor for Anomalies:</strong> Set up logging for failed logins, unexpected query errors, and suspicious input patterns (e.g., single quotes, SQL keywords in user input).</li>
          <li><strong>Alert on Suspicious Activity:</strong> Configure your SIEM or Windows Defender ATP to alert on repeated SQL errors or access to sensitive tables.</li>
          <li><strong>Investigate Incidents:</strong> Review logs for error messages like "syntax error" or "unclosed quotation mark". Correlate with user activity and IP addresses.</li>
          <li><strong>Harden the Application:</strong> Enforce parameterized queries (see code below), disable detailed error messages in production, and restrict database user privileges.</li>
          <li><strong>Learning Moment:</strong> Try simulating SQLi in a test environment and watch your logs—can you spot the attack?</li>
        </ol>
        <h5>1. Use Entity Framework Core</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Safe query using LINQ
var user = await context.Users
    .Where(u => u.Id == userId)
    .FirstOrDefaultAsync();

# Parameterized ADO.NET
using (var cmd = new SqlCommand(
    "SELECT * FROM Users WHERE Id = @UserId", conn)) 
{
    cmd.Parameters.AddWithValue("@UserId", userId);
    // ...
}
        </code></pre>
        <h5>2. IIS Web.config Settings</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<configuration>
   <system.web>
      <httpRuntime enableVersionHeader="false" 
                   requestValidationMode="2.0" />
      <pages validateRequest="true" />
   </system.web>
</configuration>
        </code></pre>
        <h5>3. Windows Defender ATP Rules</h5>
        <p>Enable SQL Server audit logging and alerts for:</p>
        <ul>
          <li>Failed login attempts</li>
          <li>Schema changes</li>
          <li>Privilege escalation attempts</li>
        </ul>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/PHP)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP web app running on Mac/Apache. Your goal is to detect and prevent SQL Injection.</p>
        <ol>
          <li><strong>Monitor Logs:</strong> Check Apache and PHP logs for SQL errors, suspicious input, and repeated failed queries.</li>
          <li><strong>Alert on Patterns:</strong> Use log monitoring tools (e.g., <strong>OSSEC</strong>, <strong>Wazuh</strong>) to alert on SQL error patterns or repeated suspicious requests.</li>
          <li><strong>Investigate:</strong> Correlate suspicious requests with user agents, IPs, and times. Look for automated scanning or brute force attempts.</li>
          <li><strong>Harden:</strong> Use PDO prepared statements (see below), disable <code>magic_quotes_gpc</code>, and set <code>sql.safe_mode</code> to On. Limit DB user privileges.</li>
          <li><strong>Learning Moment:</strong> Try running a SQLi scanner against your test app and see what shows up in your logs.</li>
        </ol>
        <h5>1. PDO Prepared Statements</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();
        </code></pre>
        <h5>2. Apache ModSecurity Rules</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# In httpd.conf or .htaccess
SecRule REQUEST_URI|REQUEST_BODY "@detectSQLi" \
    "id:981231,phase:2,block,msg:'SQL Injection Attack'"
        </code></pre>
        <h5>3. PHP Configuration</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# php.ini settings
magic_quotes_gpc = Off
sql.safe_mode = On
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux/Node.js)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Node.js app on Linux. Your goal is to detect and prevent SQL Injection.</p>
        <ol>
          <li><strong>Monitor:</strong> Use <strong>fail2ban</strong>, <strong>OSSEC</strong>, or <strong>ELK Stack</strong> to monitor logs for SQL errors and suspicious requests.</li>
          <li><strong>Alert:</strong> Set up alerts for repeated SQL errors, access to sensitive endpoints, or unusual query patterns.</li>
          <li><strong>Investigate:</strong> Review logs for error messages, correlate with user/IP, and check for automated attacks.</li>
          <li><strong>Harden:</strong> Use ORM/query builders (see below), enable ModSecurity on Nginx, and restrict DB user privileges.</li>
          <li><strong>Learning Moment:</strong> Simulate SQLi in a test app and see what your monitoring tools catch.</li>
        </ol>
        <h5>1. Use ORM/Query Builders</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Sequelize ORM
const user = await User.findOne({
  where: { id: userId }
});

# Knex Query Builder
const users = await knex('users')
  .where({ id: userId })
  .select();
        </code></pre>
        <h5>2. ModSecurity on Nginx</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# nginx.conf
location / {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
}
        </code></pre>
        <h5>3. AppArmor Profile</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# /etc/apparmor.d/usr.sbin.mysqld
/usr/sbin/mysqld {
    /var/lib/mysql/ r,
    /var/lib/mysql/** rwk,
    /var/log/mysql/ r,
    /var/log/mysql/* rw,
}
        </code></pre>
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
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for XSS vulnerabilities. Your goal is to determine if user input is being rendered in a web page without proper sanitization.</p>
        <ol>
          <li><strong>Identify Input Points:</strong> Look for places where user input is rendered in the web page (e.g., comments, error messages, profile fields).</li>
          <li><strong>Test for Injection:</strong> Enter a script or HTML tag in input fields and observe if it is rendered in the output.</li>
          <li><strong>Confirm Vulnerability:</strong> Try payloads like <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> or <code>&lt;img src=x onerror=alert(1)&gt;</code>.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>Burp Suite</strong> or <strong>OWASP ZAP</strong> for automated testing.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you execute a script in another user's browser? What happens if you use different payloads?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender responsible for a .NET web application. Your goal is to detect, prevent, and respond to XSS attacks.</p>
        <ol>
          <li><strong>Monitor for Anomalies:</strong> Set up logging for unusual request patterns, suspicious input, and unusual response times.</li>
          <li><strong>Alert on Suspicious Activity:</strong> Configure your SIEM or Windows Defender ATP to alert on repeated XSS attempts or access to sensitive pages.</li>
          <li><strong>Investigate Incidents:</strong> Review logs for unusual request patterns, suspicious input, and unusual response times.</li>
          <li><strong>Harden the Application:</strong> Implement CSP headers, use safe libraries, and sanitize all user inputs.</li>
          <li><strong>Learning Moment:</strong> Try running a XSS scanner against your test app and see what shows up in your logs.</li>
        </ol>
        <h5>1. Use built-in XSS protection</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# In Startup.cs
app.Use(async (context, next) => {
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    await next();
});
        </code></pre>
        <h5>2. Implement CSP headers</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/PHP)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP web app running on Mac/Apache. Your goal is to detect and prevent XSS.</p>
        <ol>
          <li><strong>Monitor Logs:</strong> Check Apache and PHP logs for unusual request patterns, suspicious input, and unusual response times.</li>
          <li><strong>Alert:</strong> Set up alerts for unusual request patterns, suspicious input, and unusual response times.</li>
          <li><strong>Investigate:</strong> Correlate suspicious requests with user agents, IPs, and times. Look for unusual patterns or access to sensitive pages.</li>
          <li><strong>Harden:</strong> Use safe libraries, sanitize all user inputs, and implement CSP headers.</li>
          <li><strong>Learning Moment:</strong> Try running a XSS scanner against your test app and see what shows up in your logs.</li>
        </ol>
        <h5>1. PDO Prepared Statements</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();
        </code></pre>
        <h5>2. Apache ModSecurity Rules</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# In httpd.conf or .htaccess
SecRule REQUEST_URI|REQUEST_BODY "@detectSQLi" \
    "id:981231,phase:2,block,msg:'SQL Injection Attack'"
        </code></pre>
        <h5>3. PHP Configuration</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# php.ini settings
magic_quotes_gpc = Off
sql.safe_mode = On
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux/Nginx/Node.js)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Node.js app on Linux. Your goal is to detect and prevent XSS.</p>
        <ol>
          <li><strong>Monitor:</strong> Use <strong>fail2ban</strong>, <strong>OSSEC</strong>, or <strong>ELK Stack</strong> to monitor logs for unusual request patterns, suspicious input, and unusual response times.</li>
          <li><strong>Alert:</strong> Set up alerts for unusual request patterns, suspicious input, and unusual response times.</li>
          <li><strong>Investigate:</strong> Correlate suspicious requests with user agents, IPs, and times. Look for unusual patterns or access to sensitive pages.</li>
          <li><strong>Harden:</strong> Use ORM/query builders (see below), enable ModSecurity on Nginx, and restrict access to sensitive pages.</li>
          <li><strong>Learning Moment:</strong> Try running a XSS scanner against your test app and see what shows up in your logs.</li>
        </ol>
        <h5>1. Use ORM/Query Builders</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Sequelize ORM
const user = await User.findOne({
  where: { id: userId }
});

# Knex Query Builder
const users = await knex('users')
  .where({ id: userId })
  .select();
        </code></pre>
        <h5>2. ModSecurity on Nginx</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# nginx.conf
location / {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
}
        </code></pre>
        <h5>3. AppArmor Profile</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# /etc/apparmor.d/usr.sbin.mysqld
/usr/sbin/mysqld {
    /var/lib/mysql/ r,
    /var/lib/mysql/** rwk,
    /var/log/mysql/ r,
    /var/log/mysql/* rw,
}
        </code></pre>
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
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for broken access control. Your goal is to determine if users can access resources they shouldn't be able to access.</p>
        <ol>
          <li><strong>Identify Access Points:</strong> Look for places where access control is not enforced (e.g., admin pages, user profile sections).</li>
          <li><strong>Test for Access:</strong> Try accessing resources with different user roles or IDs.</li>
          <li><strong>Confirm Vulnerability:</strong> Verify if the server enforces access control.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>Burp Suite</strong> or <strong>OWASP ZAP</strong> for automated testing.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you access resources with different roles? What happens if you use different IDs?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/.NET)</h4>
        <p><strong>Scenario:</strong> You are a defender for a .NET web app. Your goal is to detect and prevent broken access control.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all access to sensitive endpoints and failed access attempts. Use Windows Event Logs and your SIEM to track privilege escalation or unauthorized access.</li>
          <li><strong>Alert:</strong> Set up alerts for repeated access denials, privilege changes, or access to admin endpoints by non-admin users.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious access patterns, correlate with user roles and IPs, and check for privilege escalation attempts.</li>
          <li><strong>Harden:</strong> Enforce server-side access control (see code), use role-based authorization, and deny by default.</li>
          <li><strong>Learning Moment:</strong> Simulate role tampering in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Enforce Role Checks</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
[Authorize(Roles = "Admin")]
public IActionResult AdminOnly() {
   // ...
}
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/Apache/PHP)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP app on Apache. Your goal is to detect and prevent broken access control.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all access to sensitive directories and failed access attempts. Use Apache logs and tools like OSSEC.</li>
          <li><strong>Alert:</strong> Set up alerts for repeated access denials or access to restricted directories.</li>
          <li><strong>Investigate:</strong> Correlate logs with user agents, IPs, and times. Look for privilege escalation or direct object reference attempts.</li>
          <li><strong>Harden:</strong> Use .htaccess to deny by default, enforce checks in PHP code, and avoid exposing direct object references.</li>
          <li><strong>Learning Moment:</strong> Try accessing restricted directories as a non-admin and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Directory-level Security</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<Directory /var/www/html/secure>
   Require all denied
</Directory>
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux/Nginx/Node.js)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Node.js app on Linux. Your goal is to detect and prevent broken access control.</p>
        <ol>
          <li><strong>Monitor:</strong> Use ELK Stack or OSSEC to monitor access to sensitive endpoints and failed access attempts.</li>
          <li><strong>Alert:</strong> Set up alerts for repeated access denials, privilege changes, or access to admin endpoints by non-admin users.</li>
          <li><strong>Investigate:</strong> Review logs for suspicious access patterns, correlate with user roles and IPs, and check for privilege escalation attempts.</li>
          <li><strong>Harden:</strong> Implement middleware for server-side checks, deny by default, and avoid exposing direct object references.</li>
          <li><strong>Learning Moment:</strong> Simulate privilege escalation in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Middleware for Access Control</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }
  next();
}

app.get('/api/v1/docs/:id', requireAdmin, (req, res) => {
   // ...
});
        </code></pre>
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
New-AppLockerPolicy -RuleType Path -PathCondition "C:\\Windows\\*" -User Everyone -Action Allow
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
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for sensitive data exposure. Your goal is to determine if sensitive data is being exposed in the network traffic.</p>
        <ol>
          <li><strong>Identify Network Traffic:</strong> Use tools like <strong>Wireshark</strong> or <strong>tcpdump</strong> to capture network traffic.</li>
          <li><strong>Analyze Traffic:</strong> Look for patterns or data that might be sensitive (e.g., API keys, passwords, credit card numbers).</li>
          <li><strong>Confirm Vulnerability:</strong> Verify if the data is being exposed in plaintext or if SSL/TLS is being bypassed.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>SSLstrip</strong> for detecting HTTPS downgrade attacks.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you decrypt the traffic? What happens if you use different tools or techniques?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Windows-based app. Your goal is to detect and prevent sensitive data exposure and cryptographic failures.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all access to sensitive data, failed decryption attempts, and use of weak cryptography. Use Windows Event Logs and your SIEM to track sensitive data access.</li>
          <li><strong>Alert:</strong> Set up alerts for access to sensitive files, use of deprecated crypto algorithms, or failed encryption/decryption events.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized access, plaintext secrets, or use of weak crypto. Correlate with user actions and privilege levels.</li>
          <li><strong>Harden:</strong> Use DPAPI or Azure Key Vault for secrets, enforce strong encryption, and scan for hardcoded secrets in code repos.</li>
          <li><strong>Learning Moment:</strong> Simulate a secrets scan and see what your monitoring tools catch.</li>
        </ol>
        <h5>1. Windows Data Protection API</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using DPAPI
byte[] entropy = new byte[16];
new RNGCryptoServiceProvider().GetBytes(entropy);

byte[] encryptedData = ProtectedData.Protect(
    plaintext,
    entropy,
    DataProtectionScope.CurrentUser
);
        </code></pre>
        <h5>2. Azure Key Vault Integration</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
var client = new SecretClient(
    new Uri("https://your-vault.vault.azure.net/"),
    new DefaultAzureCredential()
);

KeyVaultSecret secret = await client.GetSecretAsync("secret-name");
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/PHP)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP app on Mac. Your goal is to detect and prevent sensitive data exposure and cryptographic failures.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all access to sensitive data, failed decryption attempts, and use of weak cryptography. Use system logs and tools like OSSEC to track sensitive data access.</li>
          <li><strong>Alert:</strong> Set up alerts for access to sensitive files, use of deprecated crypto algorithms, or failed encryption/decryption events.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized access, plaintext secrets, or use of weak crypto. Correlate with user actions and privilege levels.</li>
          <li><strong>Harden:</strong> Use environment variables for secrets, enforce strong encryption, and scan for hardcoded secrets in code repos.</li>
          <li><strong>Learning Moment:</strong> Simulate a secrets scan and see what your monitoring tools catch.</li>
        </ol>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Linux app. Your goal is to detect and prevent sensitive data exposure and cryptographic failures.</p>
        <ol>
          <li><strong>Monitor:</strong> Use auditd, OSSEC, or ELK Stack to monitor access to sensitive files, failed decryption attempts, and use of weak cryptography.</li>
          <li><strong>Alert:</strong> Set up alerts for access to sensitive files, use of deprecated crypto algorithms, or failed encryption/decryption events.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized access, plaintext secrets, or use of weak crypto. Correlate with user actions and privilege levels.</li>
          <li><strong>Harden:</strong> Use environment variables for secrets, enforce strong encryption, and scan for hardcoded secrets in code repos.</li>
          <li><strong>Learning Moment:</strong> Simulate a secrets scan and see what your monitoring tools catch.</li>
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
libxml.disable_entity_loader = On
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
        <p><strong>Scenario:</strong> You are a security tester assessing a web application for security misconfiguration. Your goal is to determine if common security practices are being followed.</p>
        <ol>
          <li><strong>Identify Configuration Points:</strong> Look for places where security settings are defined (e.g., web.config, .htaccess, environment variables).</li>
          <li><strong>Test for Misconfiguration:</strong> Try accessing debug endpoints, checking security headers, or testing CORS misconfiguration.</li>
          <li><strong>Confirm Vulnerability:</strong> Verify if the application is vulnerable to common security misconfigurations.</li>
          <li><strong>Automate Testing:</strong> Use tools like <strong>curl</strong> for automated testing.</li>
          <li><strong>Learning Moment:</strong> Try these steps on a safe test environment like <a href="https://owasp.org/www-project-juice-shop/" target="_blank">OWASP Juice Shop</a> or <a href="http://dvwa.co.uk/" target="_blank">DVWA</a>.</li>
        </ol>
        <p><em>What to try next:</em> Can you find more misconfigurations? What happens if you use different tools or techniques?</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team Walkthrough (Windows/IIS)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Windows/IIS app. Your goal is to detect and prevent security misconfigurations.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all configuration changes, failed logins, and access to debug endpoints. Use Windows Event Logs and your SIEM to track configuration activity.</li>
          <li><strong>Alert:</strong> Set up alerts for changes to web.config, access to debug endpoints, or use of default credentials.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized changes, access to sensitive endpoints, or use of weak/default settings.</li>
          <li><strong>Harden:</strong> Enforce secure defaults, remove unused features, and keep systems up to date (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate a misconfiguration in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. IIS Hardening</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<!-- web.config security -->
<configuration>
  <system.web>
    <compilation debug="false"/>
    <trace enabled="false"/>
    <customErrors mode="On"/>
  </system.web>
  <system.webServer>
    <security>
      <requestFiltering removeServerHeader="true"/>
    </security>
  </system.webServer>
</configuration>
        </code></pre>
        <h5>2. Security Headers</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<httpProtocol>
  <customHeaders>
    <add name="X-Frame-Options" value="DENY"/>
    <add name="X-Content-Type-Options" value="nosniff"/>
    <remove name="X-Powered-By"/>
  </customHeaders>
</httpProtocol>
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team Walkthrough (Mac/Apache)</h4>
        <p><strong>Scenario:</strong> You are a defender for a PHP app on Mac/Apache. Your goal is to detect and prevent security misconfigurations.</p>
        <ol>
          <li><strong>Monitor:</strong> Log all configuration changes, failed logins, and access to debug endpoints. Use Apache logs and tools like OSSEC to track configuration activity.</li>
          <li><strong>Alert:</strong> Set up alerts for changes to .htaccess, access to debug endpoints, or use of default credentials.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized changes, access to sensitive endpoints, or use of weak/default settings.</li>
          <li><strong>Harden:</strong> Enforce secure defaults, remove unused features, and keep systems up to date (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate a misconfiguration in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Apache Security Configuration</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Security headers in .htaccess
Header set X-Frame-Options "DENY"
Header set X-Content-Type-Options "nosniff"
Header set Content-Security-Policy "default-src 'self'"
Header unset X-Powered-By

# Disable directory listing
Options -Indexes

# Restrict access to sensitive files
<FilesMatch "^\.">
    Order allow,deny
    Deny from all
</FilesMatch>
        </code></pre>
        <h5>2. PHP Hardening</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# php.ini security settings
display_errors = Off
expose_php = Off
session.cookie_httponly = 1
session.cookie_secure = 1
allow_url_fopen = Off
        </code></pre>
      `,
      blueTeamLinux: `
        <h4>Blue Team Walkthrough (Linux/Nginx)</h4>
        <p><strong>Scenario:</strong> You are a defender for a Linux/Nginx app. Your goal is to detect and prevent security misconfigurations.</p>
        <ol>
          <li><strong>Monitor:</strong> Use auditd, OSSEC, or ELK Stack to monitor configuration changes, failed logins, and access to debug endpoints.</li>
          <li><strong>Alert:</strong> Set up alerts for changes to nginx.conf, access to debug endpoints, or use of default credentials.</li>
          <li><strong>Investigate:</strong> Review logs for unauthorized changes, access to sensitive endpoints, or use of weak/default settings.</li>
          <li><strong>Harden:</strong> Enforce secure defaults, remove unused features, and keep systems up to date (see code below).</li>
          <li><strong>Learning Moment:</strong> Simulate a misconfiguration in a test app and see if your monitoring catches it.</li>
        </ol>
        <h5>1. Nginx Hardening</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# nginx.conf security settings
server {
    # Hide version number
    server_tokens off;
    
    # Security headers
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";
    add_header Content-Security-Policy "default-src 'self'";
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;ECDHE-RSA-AES128-GCM-SHA256;
}
        </code></pre>
        <h5>2. System Hardening</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Update package lists
apt update && apt upgrade

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw enable

# Secure shared memory
echo "tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
        </code></pre>
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
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
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
AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
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
          <li><strong>Investigate:</strong> Review logs for repeated failed logins, privilege escalation, or unusual process activity.</li>
          <li><strong>Harden:</strong> Protect log files with proper permissions and use logrotate to retain logs.</li>
          <li><strong>Learning Moment:</strong> Simulate attacks and verify your monitoring and alerting works.</li>
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
    }
  }
};

export default proactiveControlsData;
export const vulnerabilityGuides = proactiveControlsData.vulnerabilityGuides;
