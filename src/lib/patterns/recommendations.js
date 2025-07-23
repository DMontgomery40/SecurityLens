// Recommendations for each pattern (used in normal "CVE Details" view)
export const recommendations = {
  sqlInjection: {
    recommendation: `
Why it Matters: SQL injection can allow attackers to read, modify, or delete database data.

What to Do:
1. Use parameterized queries or prepared statements
2. Never concatenate user input into SQL strings
3. Validate and sanitize all inputs

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const userId = '123';  // Example user input
query("SELECT * FROM users WHERE id = " + userId);    // Direct concatenation
query(\`SELECT * FROM users WHERE id = \${userId}\`);  // Template literals still vulnerable
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
query("SELECT * FROM users WHERE id = ?", [userId]);  // Parameterized query
// Or with an ORM:
User.findById(userId);                                // Safe abstraction
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A03 Injection',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      },
      {
        title: 'OWASP SQL Injection Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
      },
      {
        title: 'CWE-89: SQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/89.html'
      }
    ],
    cwe: '89'
  },

  commandInjection: {
    recommendation: `
Why it Matters: Command injection can allow attackers to execute arbitrary system commands.

What to Do:
1. Avoid command execution if possible
2. Use safer alternatives like APIs or libraries
3. If necessary, use strict input validation and command arrays

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const userInput = 'user-supplied-command';  // Example user input
const domain = 'user-supplied-domain';      // Example domain input

exec('git ' + userInput);              // Command injection
system('ping ' + domain);              // System command injection
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
execFile('git', [userInput]);          // Array of arguments
spawn('ping', [domain]);               // Safer alternative
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-77: Command Injection',
        url: 'https://cwe.mitre.org/data/definitions/77.html'
      },
      {
        title: 'OWASP Command Injection Prevention',
        url: 'https://owasp.org/www-community/attacks/Command_Injection'
      },
      {
        title: 'A03 Injection',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    cwe: '77'
  },

  brokenAuth: {
    recommendation: `
Why it Matters: Weak authentication can allow unauthorized access to sensitive functionality.

What to Do:
1. Use strong password hashing (bcrypt/Argon2)
2. Implement proper session management
3. Use multi-factor authentication where possible

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Plain text comparison
if (password === storedPassword) {     
  login(user);
}

// Weak hashing
const hash = md5(password);            
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Strong hashing with salt
const salt = await bcrypt.genSalt(10);
const hash = await bcrypt.hash(password, salt);

// Secure comparison
const match = await bcrypt.compare(password, storedHash);
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A07 Identification and Authentication Failures',
        url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
      },
      {
        title: 'OWASP Authentication Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
      },
      {
        title: 'CWE-287: Improper Authentication',
        url: 'https://cwe.mitre.org/data/definitions/287.html'
      }
    ],
    cwe: '287'
  },

  sensitiveExposure: {
    recommendation: `
Why it Matters: Exposing sensitive data like API keys or credentials can lead to unauthorized access and account takeover.

What to Do:
1. Never hardcode sensitive data in source code
2. Use environment variables or secure vaults
3. Implement proper encryption for sensitive data storage
4. Use secrets scanning tools (e.g., GitGuardian, TruffleHog) to detect accidental leaks
5. Consider cloud KMS (Key Management Services) for managing secrets at scale

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const apiKey = "1234-abcd-5678-efgh";     // Hardcoded credentials
const password = "secretPassword123";      // Plaintext secrets
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const apiKey = process.env.API_KEY;        // Environment variable
const password = await vault.getSecret();   // Secure storage
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-200: Exposure of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/200.html'
      },
      {
        title: 'OWASP Sensitive Data Exposure',
        url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
      },
      {
        title: 'A02 Cryptographic Failures',
        url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
      }
    ],
    cwe: '200'
  },

  xxeVulnerability: {
    recommendation: `
Why it Matters: XXE vulnerabilities can lead to data disclosure, denial of service, and server-side request forgery.

What to Do:
1. Disable XML external entity processing
2. Use safe XML parsers and configurations
3. Validate and sanitize XML input

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const input = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';  // Example malicious XML
const parser = new DOMParser();            // Default config may be unsafe
const xml = parser.parseFromString(input); // No entity restrictions
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const parser = new DOMParser({
  resolveExternalEntities: false,          // Disable external entities
  loadExternalDtd: false                   // Disable DTD loading
});
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-611: Improper Restriction of XML External Entity Reference',
        url: 'https://cwe.mitre.org/data/definitions/611.html'
      },
      {
        title: 'OWASP XXE Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '611'
  },

  xssVulnerability: {
    recommendation: `
Why it Matters: Cross-Site Scripting allows attackers to execute malicious scripts in users' browsers.

What to Do:
1. Use content security policy (CSP)
2. Encode/escape all user input
3. Use safe JavaScript frameworks/libraries (modern frameworks like React, Vue, and Angular are safer by default, as they escape content automatically)

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const userInput = '<script>alert("xss")</script>';  // Example malicious input
element.innerHTML = userInput;           // Direct DOM manipulation
document.write(data);                    // Unsafe document writing
    </code>
</pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
element.textContent = userInput;         // Safe text assignment
const escaped = escapeHtml(userInput);   // Proper escaping
const template = sanitize(htmlTemplate); // Use sanitizer
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A03 Injection',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      },
      {
        title: 'OWASP XSS Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
      },
      {
        title: 'CWE-79: Cross-site Scripting',
        url: 'https://cwe.mitre.org/data/definitions/79.html'
      }
    ],
    cwe: '79'
  },

  brokenAccessControl: {
    recommendation: `
Why it Matters: Broken access control moves up from the fifth position to #1. The 34 CWEs mapped to Broken Access Control had more occurrences in applications than any other category.

What to Do:
1. Enforce access control through a trusted server-side component
2. Deny access by default, unless explicitly allowed
3. Implement access control mechanisms once and re-use them throughout the application

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Client-side access control
if(user.isAdmin) {             // Can be manipulated in browser
  showAdminPanel();
}

// Direct object references without checks
app.get('/api/v1/docs/:id');   // No ownership verification
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Server-side enforcement
await enforceUserPermissions(user, 'admin');
if(await canAccessDocument(user, docId)) {
  // Allow access
}
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A01 Broken Access Control',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      },
      {
        title: 'CWE-264: Permissions, Privileges, and Access Controls',
        url: 'https://cwe.mitre.org/data/definitions/264.html'
      }
    ],
    cwe: '264'
  },


  insecureDeserialization: {
    recommendation: `
Why it Matters: A08:2021 - Software and Data Integrity Failures is a new category focusing on making assumptions related to software updates, critical data, and CI/CD pipelines.

What to Do:
1. Use digital signatures to verify integrity
2. Use safe deserializers
3. Validate all serialized data from untrusted sources

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Unsafe deserialization
const data = pickle.loads(userInput);
const obj = yaml.load(untrustedYaml);
const config = require(userProvidedPath);
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Safe alternatives
const data = JSON.parse(userInput);        // Use JSON instead
const obj = yaml.safeLoad(untrustedYaml);  // Safe YAML loading
const config = validateConfig(userInput);  // Validate all input
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A08 Software and Data Integrity Failures',
        url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
      },
      {
        title: 'CWE-502: Deserialization of Untrusted Data',
        url: 'https://cwe.mitre.org/data/definitions/502.html'
      }
    ],
    cwe: '502'
  },


  insufficientLogging: {
    recommendation: `
Why it Matters: A09:2021 - Security Logging and Monitoring Failures moves up from #10 in 2017. Without proper logging, breaches cannot be detected or investigated.

What to Do:
1. Ensure all login, access control, and server-side input validation failures are logged
2. Ensure logs are in a format suitable for log management solutions
3. Implement proper log retention and backup
4. Use log management and monitoring platforms (e.g., ELK, Splunk, Datadog) for centralized log aggregation and alerting

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
console.log('User logged in');          // Basic console logging
console.log(error);                     // Insufficient error details
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const user = { id: '123' };        // Example user object
const error = { code: 'AUTH_FAILED' };  

logger.info('Authentication success', {
  userId: user.id,
  timestamp: new Date(),
  ipAddress: req.ip
});

logger.error('Authentication failed', {
  reason: error.code,
  timestamp: new Date()
});
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A09 Security Logging and Monitoring Failures',
        url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
      },
      {
        title: 'CWE-778: Insufficient Logging',
        url: 'https://cwe.mitre.org/data/definitions/778.html'
      }
    ],
    cwe: '778'
  },

  insecureSubmission: {
    recommendation: `
Why it Matters: Submitting sensitive data over insecure channels (HTTP) exposes it to interception and tampering.

What to Do:
1. Always use HTTPS for form submissions and API calls
2. Implement HSTS headers to enforce HTTPS
3. Educate users to look for secure connections

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
fetch('http://example.com/api/submit', { method: 'POST', body: data });
    </code>
  </pre>
  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
fetch('https://example.com/api/submit', { method: 'POST', body: data });
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A02 Cryptographic Failures',
        url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
      },
      {
        title: 'CWE-319: Cleartext Transmission of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/319.html'
      }
    ],
    cwe: '319'
  },

  securityLogging: {
    recommendation: `
Why it Matters: Insufficient logging and monitoring can prevent detection of breaches and hinder incident response.

What to Do:
1. Log all authentication, access control, and input validation failures
2. Use centralized log management and monitoring
3. Ensure logs are protected from tampering and are retained appropriately

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
console.log('User logged in');
console.log(error);
    </code>
  </pre>
  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
logger.info('Authentication success', { userId: user.id, timestamp: new Date(), ipAddress: req.ip });
logger.error('Authentication failed', { reason: error.code, timestamp: new Date() });
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A09 Security Logging and Monitoring Failures',
        url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
      },
      {
        title: 'CWE-778: Insufficient Logging',
        url: 'https://cwe.mitre.org/data/definitions/778.html'
      }
    ],
    cwe: '778'
  },

  insecureDesign: {
    recommendation: `
Why it Matters: Insecure design flaws are baked into the architecture—no patch can save you without redesign.

What to Do:
1. Perform formal threat modeling early and every sprint.
2. Treat security requirements equal to functional requirements.
3. Add abuse-case user stories and negative unit tests.
4. Enforce central authorization and idempotency checks for critical workflows.

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad"><code>
// Trusts client-provided price
const charge = req.body.price; // attacker changes to 0.01
order.total = charge;
  </code></pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good"><code>
// Server calculates authoritative price
const charge = calculatePrice(cartItems); // ignores client price
order.total = charge;
  </code></pre>
</div>`,
    references: [
      { title: 'A04 Insecure Design', url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
      { title: 'OWASP Cheat Sheet – Threat Modeling', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html' }
    ],
    cwe: '509'
  },

  hardcodedSecret: {
    recommendation: `
Why it Matters: Hardcoded credentials in source code can be found by attackers, giving direct access to privileged resources.

What to Do:
1. Never hardcode sensitive data in source code
2. Use environment variables or secure vaults
3. Implement proper encryption for sensitive data storage
4. Use secrets scanning tools (e.g., GitGuardian, TruffleHog) to detect accidental leaks

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const apiKey = "sk-1234567890abcdef";     // Hardcoded credentials
const password = "secretPassword123";      // Plaintext secrets
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const apiKey = process.env.API_KEY;        // Environment variable
const password = await vault.getSecret();   // Secure storage
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-798: Use of Hard-coded Credentials',
        url: 'https://cwe.mitre.org/data/definitions/798.html'
      },
      {
        title: 'A02 Cryptographic Failures',
        url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
      }
    ],
    cwe: '798'
  },

  noSqlInjection: {
    recommendation: `
Why it Matters: NoSQL injection can allow attackers to bypass authentication, extract data, or modify database contents.

What to Do:
1. Use parameterized queries and proper input validation
2. Implement proper access controls and authentication
3. Sanitize all user input before database operations

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Direct user input in query
const query = { $where: userInput };
db.collection.find(query);

// String concatenation
const filter = "this.name == '" + username + "'";
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Parameterized query
const query = { name: username };
db.collection.find(query);

// Input validation
const sanitizedInput = validator.escape(userInput);
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-943: NoSQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/943.html'
      },
      {
        title: 'OWASP NoSQL Injection Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '943'
  },

  weakCrypto: {
    recommendation: `
Why it Matters: Weak cryptographic algorithms can be broken by attackers, exposing sensitive data.

What to Do:
1. Use strong, modern cryptographic algorithms (SHA-256, AES-256)
2. Avoid deprecated algorithms like MD5 and SHA-1
3. Keep cryptographic libraries up to date

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const hash = crypto.createHash('md5').update(password).digest('hex');
const weakHash = crypto.createHash('sha1').update(data).digest('hex');
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const hash = crypto.createHash('sha256').update(password).digest('hex');
const strongHash = await bcrypt.hash(password, 12);
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-326: Inadequate Encryption Strength',
        url: 'https://cwe.mitre.org/data/definitions/326.html'
      },
      {
        title: 'A02 Cryptographic Failures',
        url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
      }
    ],
    cwe: '326'
  },

  insecureCryptoUsage: {
    recommendation: `
Why it Matters: Using deprecated or insecure cryptographic functions can expose data to attacks.

What to Do:
1. Replace deprecated crypto functions with modern alternatives
2. Use authenticated encryption modes
3. Follow current cryptographic best practices

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const cipher = crypto.createCipher('aes192', password);
const decipher = crypto.createDecipher('aes192', password);
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const cipher = crypto.createCipherGCM('aes-256-gcm', key, iv);
const decipher = crypto.createDecipherGCM('aes-256-gcm', key, iv);
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-327: Broken or Risky Crypto Algorithm',
        url: 'https://cwe.mitre.org/data/definitions/327.html'
      },
      {
        title: 'A02 Cryptographic Failures',
        url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
      }
    ],
    cwe: '327'
  },

  pathTraversal: {
    recommendation: `
Why it Matters: Path traversal attacks can allow attackers to access files outside the intended directory.

What to Do:
1. Validate and sanitize all file path inputs
2. Use whitelists of allowed file names and paths
3. Implement proper access controls

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const filePath = req.params.file;
fs.readFile('/uploads/' + filePath);  // Allows ../../../etc/passwd
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const path = require('path');
const safePath = path.normalize(req.params.file).replace(/^(\\.\\.[/\\\\])+/, '');
const fullPath = path.join('/uploads/', safePath);
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-23: Relative Path Traversal',
        url: 'https://cwe.mitre.org/data/definitions/23.html'
      },
      {
        title: 'OWASP Path Traversal',
        url: 'https://owasp.org/www-community/attacks/Path_Traversal'
      }
    ],
    cwe: '23'
  },

  openRedirect: {
    recommendation: `
Why it Matters: Open redirects can be used in phishing attacks to redirect users to malicious sites.

What to Do:
1. Validate redirect URLs against a whitelist
2. Use relative URLs instead of absolute ones
3. Implement proper URL validation

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const redirectUrl = req.query.redirect;
res.redirect(redirectUrl);  // Can redirect to evil.com
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const allowedUrls = ['/dashboard', '/profile', '/settings'];
if (allowedUrls.includes(redirectUrl)) {
  res.redirect(redirectUrl);
}
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-601: URL Redirection to Untrusted Site',
        url: 'https://cwe.mitre.org/data/definitions/601.html'
      },
      {
        title: 'OWASP Unvalidated Redirects and Forwards',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
      }
    ],
    cwe: '601'
  },

  ssrf: {
    recommendation: `
Why it Matters: Server-Side Request Forgery can allow attackers to make requests from your server to internal systems.

What to Do:
1. Validate and whitelist allowed URLs
2. Implement network segmentation
3. Use deny lists for private IP ranges

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const url = req.body.webhookUrl;
fetch(url);  // Can access internal services
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const allowedHosts = ['api.example.com', 'webhook.trusted.com'];
const parsedUrl = new URL(url);
if (allowedHosts.includes(parsedUrl.hostname)) {
  fetch(url);
}
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-918: Server-Side Request Forgery (SSRF)',
        url: 'https://cwe.mitre.org/data/definitions/918.html'
      },
      {
        title: 'A10 Server-Side Request Forgery',
        url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
      }
    ],
    cwe: '918'
  },

  insecureTransmission: {
    recommendation: `
Why it Matters: Transmitting data over insecure HTTP exposes it to interception and tampering.

What to Do:
1. Always use HTTPS for data transmission
2. Implement HTTP Strict Transport Security (HSTS)
3. Redirect all HTTP traffic to HTTPS

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
const apiUrl = 'http://api.example.com/data';
fetch(apiUrl, { method: 'POST', body: sensitiveData });
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
const apiUrl = 'https://api.example.com/data';
fetch(apiUrl, { method: 'POST', body: sensitiveData });
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A02 Cryptographic Failures',
        url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
      },
      {
        title: 'CWE-319: Cleartext Transmission of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/319.html'
      }
    ],
    cwe: '319'
  },

  missingObjectAuth: {
    recommendation: `
Why it Matters: Missing object-level authorization allows attackers to access or modify data they shouldn't have access to.

What to Do:
1. Implement proper authorization checks for every object access
2. Verify user ownership or permissions before allowing access
3. Use consistent authorization patterns across your API

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
app.get('/api/documents/:id', (req, res) => {
  const doc = Document.findById(req.params.id);  // No ownership check
  res.json(doc);
});
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
app.get('/api/documents/:id', authenticateUser, (req, res) => {
  const doc = Document.findById(req.params.id);
  if (doc.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json(doc);
});
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A01 Broken Access Control',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      },
      {
        title: 'CWE-284: Improper Access Control',
        url: 'https://cwe.mitre.org/data/definitions/284.html'
      }
    ],
    cwe: '284'
  },

  sessionFixation: {
    recommendation: `
Why it Matters: Session fixation allows attackers to hijack user sessions by forcing them to use a known session ID.

What to Do:
1. Generate new session IDs after authentication
2. Never accept session IDs from user input
3. Use secure session management practices

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Setting session ID from user input
req.session.id = req.query.sessionId;  // Dangerous!
req.sessionID = req.body.sid;          // Also vulnerable
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Regenerate session after login
req.session.regenerate((err) => {
  if (err) throw err;
  req.session.userId = user.id;
  req.session.save();
});
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'CWE-384: Session Fixation',
        url: 'https://cwe.mitre.org/data/definitions/384.html'
      },
      {
        title: 'OWASP Session Management Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'
      }
    ],
    cwe: '384'
  },

  suspiciousDependency: {
    recommendation: `
Why it Matters: Dependencies from untrusted sources can introduce malicious code into your application.

What to Do:
1. Only use dependencies from trusted package registries
2. Verify package integrity with checksums
3. Monitor dependencies for security updates
4. Use dependency scanning tools

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
{
  "dependencies": {
    "malicious-package": "https://evil.com/package.tar.gz"
  }
}
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
{
  "dependencies": {
    "trusted-package": "^1.2.3"  // From npm registry
  }
}
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A06 Vulnerable and Outdated Components',
        url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
      },
      {
        title: 'CWE-1104: Use of Unmaintained Third Party Components',
        url: 'https://cwe.mitre.org/data/definitions/1104.html'
      }
    ],
    cwe: '1104'
  },
};