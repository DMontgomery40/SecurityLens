// Categories
export const patternCategories = {
  ACCESS_CONTROL: '264',      // A01:2021 - Broken Access Control
  CRYPTO_FAILURES: '310',     // A02:2021 - Cryptographic Failures
  INJECTION: '74',            // A03:2021 - Injection
  INSECURE_DESIGN: '509',     // A04:2021 - Insecure Design
  SECURITY_MISCONFIG: '16',   // A05:2021 - Security Misconfiguration
  VULNERABLE_COMPONENTS: '937', // A06:2021 - Vulnerable Components
  AUTH_FAILURES: '287',       // A07:2021 - Auth & Verification Failures
  INTEGRITY_FAILURES: '494',  // A08:2021 - Software & Data Integrity
  LOGGING_FAILURES: '778',    // A09:2021 - Security Logging Failures
  SSRF: '918'                // A10:2021 - SSRF
};
// Categories

// Refined Patterns
export const patterns = {
  // SQL & Command Injection
  sqlInjection: {
    pattern: /\b(?:select|insert|update|delete|drop|alter|create)\b[^;]*\b(?:from|into|where)\b/i,
    description: 'A03:2021 - Injection - SQL injection allowing direct data access or system compromise',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89',
    cwe: '89'
  },

  commandExecution: {
    pattern: /\b(?:exec|eval|system|os\.popen|subprocess\.call)\b/i,
    description: 'A03:2021 - Injection - Command execution allowing system compromise',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '77',
    cwe: '77'
  },

  // Authentication & Access
  brokenAuth: {
    pattern: /\b(?:password|passwd|admin|login)\b/i,
    description: 'Potential authentication vulnerability',
    severity: 'HIGH',
    category: patternCategories.AUTH_FAILURES,
    subcategory: '287',
    cwe: '287'
  },

  sensitiveExposure: {
    pattern: /\b(?:apikey|secretkey|password|credentials)\b/i,
    description: 'A02:2021 - Cryptographic Failures - Exposure of sensitive data',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_FAILURES,
    subcategory: '200',
    cwe: '200'
  },

  // XXE & XSS
  xxeVulnerability: {
    pattern: /\b<!ENTITY\b/i,
    description: 'A05:2021 - Security Misconfiguration - XML parsing vulnerabilities',
    severity: 'MEDIUM',
    category: patternCategories.INJECTION,
    subcategory: '611',
    cwe: '611'
  },

  xssVulnerability: {
    pattern: /<\s*script\b[^>]*>[^<]*<\s*\/\s*script\s*>|\b(?:alert|document\.write|eval\(|javascript:|<\s*img\b[^>]*\sonerror\b)/i,
    description: 'A03:2021 - Injection - Cross-site scripting enabling client-side attacks',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79',
    cwe: '79'
  },

  // Access Control & Configuration
  brokenAccessControl: {
    pattern: /\b(?:admin=true|role=admin|isAdmin|auth\.check|permissions|authorize)\b/i,
    description: 'A01:2021 - Broken Access Control - Unauthorized access to protected functionality',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '264',
    cwe: '264'
  },

  securityMisconfig: {
    pattern: /\b(?:debug=True|verbose=True)\b/i,
    description: 'A05:2021 - Security Misconfiguration - Insecure configuration settings',
    severity: 'MEDIUM',
    category: patternCategories.SECURITY_MISCONFIG,
    subcategory: '16',
    cwe: '16'
  },

  // Deserialization & Components
  insecureDeserialization: {
    pattern: /\b(?:pickle|cPickle|unpickle|pyYAML|yaml\.load)\b/i,
    description: 'A08:2021 - Software and Data Integrity Failures - Unsafe deserialization of data',
    severity: 'MEDIUM',
    category: patternCategories.INTEGRITY_FAILURES,
    subcategory: '502',
    cwe: '502'
  },

  knownVulnComponents: {
    pattern: /\b(?:django|flask|rails|struts|phpmyadmin)\b/i,
    description: 'A06:2021 - Vulnerable Components - Potentially outdated dependencies',
    severity: 'LOW',
    category: patternCategories.VULNERABLE_COMPONENTS,
    subcategory: '937',
    cwe: '937'
  },

  // Logging
  insufficientLogging: {
    pattern: /\b(?:print|console\.log)\b/i,
    description: 'A09:2021 - Security Logging and Monitoring Failures - Inadequate logging practices',
    severity: 'LOW',
    category: patternCategories.LOGGING_FAILURES,
    subcategory: '778',
    cwe: '778'
  }
};

// After the patterns object
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

  commandExecution: {
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
3. Use safe JavaScript frameworks/libraries

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

  securityMisconfig: {
    recommendation: `
Why it Matters: A05:2021 - Security Misconfiguration moves up from #6 in 2017. 90% of applications were tested for some form of misconfiguration.

What to Do:
1. Use secure default configurations
2. Remove unused features and frameworks
3. Keep all systems and dependencies up to date

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Development settings in production
DEBUG=True
SHOW_ERRORS=True
    
// Default/weak configurations
app.use(cors());               // Allow all origins
app.use(helmet());            // Without customization
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Production-safe settings
DEBUG=False
SHOW_ERRORS=False

// Secure configurations
app.use(cors({
  origin: ['https://trusted-origin.com'],
  methods: ['GET', 'POST']
}));
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A05 Security Misconfiguration',
        url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
      },
      {
        title: 'CWE-16: Configuration',
        url: 'https://cwe.mitre.org/data/definitions/16.html'
      }
    ],
    cwe: '16'
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
const config = validateConfig(userInput);   // Validate all input
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

  knownVulnComponents: {
    recommendation: `
Why it Matters: A06:2021 - Vulnerable and Outdated Components was previously titled Using Components with Known Vulnerabilities and #2 in Top 10 2017.

What to Do:
1. Remove unused dependencies
2. Continuously inventory versions of all components
3. Monitor security databases for vulnerabilities

<div class="example-block">
  <div class="example-label">❌ Vulnerable:</div>
  <pre class="code-block bad">
    <code>
// Outdated dependencies
{
  "dependencies": {
    "express": "^4.16.0",
    "lodash": "^4.17.15"
  }
}
    </code>
  </pre>

  <div class="example-label">✅ Safe:</div>
  <pre class="code-block good">
    <code>
// Updated dependencies with security fixes
{
  "dependencies": {
    "express": "^4.17.3",
    "lodash": "^4.17.21"
  }
}
// Regular security audits
$ npm audit
$ npm audit fix
    </code>
  </pre>
</div>`,
    references: [
      {
        title: 'A06 Vulnerable and Outdated Components',
        url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
      },
      {
        title: 'CWE-937: Using Components with Known Vulnerabilities',
        url: 'https://cwe.mitre.org/data/definitions/937.html'
      }
    ],
    cwe: '937'
  },

  insufficientLogging: {
    recommendation: `
Why it Matters: A09:2021 - Security Logging and Monitoring Failures moves up from #10 in 2017. Without proper logging, breaches cannot be detected.

What to Do:
1. Ensure all login, access control, and server-side input validation failures are logged
2. Ensure logs are in a format suitable for log management solutions
3. Implement proper log retention and backup

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
const user = { id: '123' };  // Example user object
const attempt = { ip: '1.2.3.4' };  // Example attempt object
const error = { code: 'AUTH_FAILED' };  // Example error object

logger.info('Authentication success', {
  userId: user.id,
  timestamp: new Date(),
  ipAddress: req.ip
});

logger.error('Authentication failed', {
  attempt: attempt,
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
  }
};
