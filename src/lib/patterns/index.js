// Categories
export const patternCategories = {
  CRITICAL_EXECUTION: '94',    // Code injection/execution
  AUTHENTICATION: '287',       // Auth bypass/missing auth
  INJECTION: '74',             // Various injection types (SQL, Command, etc)
  CRYPTO_ISSUES: '310',        // Cryptographic/encryption issues
  MEMORY_BUFFER: '119',        // Buffer/memory issues
  DATA_PROTECTION: '200',      // Sensitive data exposure
  INPUT_VALIDATION: '20',      // Input validation issues
  ERROR_HANDLING: '389',       // Error handling & logging
  ACCESS_CONTROL: '264',       // Permission & privilege issues
  RESOURCE_MGMT: '399',        // Resource management & leaks
  SSRF: '918',                 // Server-Side Request Forgery
  SESSION_MANAGEMENT: '384',   // Session management issues
  API_SECURITY: '920',         // API Security issues
  DEPENDENCY_MANAGEMENT: '925' // Dependency-related issues
};

// Consolidated Patterns
export const patterns = {
  // Execution Patterns
  evalExecution: {
    pattern: /eval\s*\([^)]*\)|new\s+Function\s*\(/,
    description: 'Dangerous code execution via eval() or Function constructor',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '95',
    cwe: '95'
  },
  commandInjection: {
    pattern: /child_process\.exec\s*\(|\.exec\s*\(|\.spawn\s*\(/,
    description: 'Potential command injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '77',
    cwe: '77'
  },

  // Authentication Patterns
  missingAuth: {
    pattern: /authentication:\s*false|auth:\s*false|noAuth:\s*true|skipAuth/i,
    description: 'Authentication bypass or missing authentication',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '306',
    cwe: '306'
  },
  hardcodedCreds: {
    pattern: /(password|secret|key|token|credential)s?\s*[:=]\s*['"][^'"]+['"]/i,
    description: 'Hardcoded credentials detected',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '798',
    cwe: '798'
  },

  // Injection Patterns
  sqlInjection: {
    pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
    description: 'Potential SQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89',
    cwe: '89'
  },
  xssVulnerability: {
    pattern: /innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|\$\(.*\)\.html\s*\(/,
    description: 'Cross-site scripting vulnerability',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79',
    cwe: '79'
  },
  noSqlInjection: {
    pattern: /\$where\s*:\s*['"]|\.find\s*\(\s*{[^}]*\$regex/,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '943',
    cwe: '943'
  },

  // Cryptography Patterns
  weakCrypto: {
    pattern: /crypto\.createHash\s*\(\s*['"]md5['"]\)|crypto\.createHash\s*\(\s*['"]sha1['"]\)/,
    description: 'Use of weak cryptographic hash function',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_ISSUES,
    subcategory: '326',
    cwe: '326'
  },
  insecureCryptoUsage: {
    pattern: /crypto\.createCipher\s*\(|crypto\.createDecipher\s*\(/,
    description: 'Use of deprecated cryptographic functions',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_ISSUES,
    subcategory: '927',
    cwe: '927'
  },

  // Memory Patterns
  bufferIssue: {
    pattern: /Buffer\.allocUnsafe\s*\(|new\s+Buffer\s*\(/,
    description: 'Unsafe buffer allocation',
    severity: 'HIGH',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '119',
    cwe: '119'
  },
  memoryLeak: {
    pattern: /(setInterval|setTimeout)\s*\([^,]+,[^)]+\)/,
    description: 'Potential memory leak in timer/interval',
    severity: 'MEDIUM',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '401',
    cwe: '401'
  },

  // Data Protection Patterns
  sensitiveData: {
    pattern: /(password|token|secret|key|credential)s?\s*=\s*[^;]+/i,
    description: 'Sensitive data exposure',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '200',
    cwe: '200'
  },
  insecureTransmission: {
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/,
    description: 'Potential insecure data transmission',
    severity: 'MEDIUM',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '319',
    cwe: '319'
  },

  // Error Handling Patterns
  sensitiveErrorInfo: {
    pattern: /catch\s*\([^)]*\)\s*{\s*(?:console\.(?:log|error)|res\.(?:json|send))\s*\([^)]*(?:err|error)/,
    description: 'Potential sensitive information in error messages',
    severity: 'MEDIUM',
    category: patternCategories.ERROR_HANDLING,
    subcategory: '209',
    cwe: '209'
  },

  // Access Control Patterns
  insecureDirectObjectRef: {
    pattern: /\b(?:user|account|file|document)Id\s*=\s*(?:params|query|body|req)\.[a-zA-Z_][a-zA-Z0-9_]*/,
    description: 'Potential Insecure Direct Object Reference (IDOR)',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '639',
    cwe: '639'
  },
  improperAuthorizationChecks: {
    pattern: /if\s*\(\s*(!?req\.user\.isAdmin\s*|\s*!req\.user\.hasPermission)/,
    description: 'Improper authorization checks allowing unauthorized access',
    severity: 'CRITICAL',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '306',
    cwe: '306'
  },

  // Input Validation Patterns
  pathTraversal: {
    pattern: /(?:\.\.\/|\.\.\\|\.\.[/\\])[^/\\]*/,
    description: 'Potential path traversal vulnerability',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '23',
    cwe: '23'
  },
  unsanitizedInputUsage: {
    pattern: /process\.env\.[^;\n]+|config\.[a-zA-Z0-9_]+\s*=\s*req\.[a-zA-Z0-9_]+/,
    description: 'Unsanitized user input used in sensitive operations',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '932',
    cwe: '932'
  },

  // Resource Management Patterns
  openRedirect: {
    pattern: /(?:res\.redirect|window\.location|location\.href)\s*=\s*(?:req\.(?:query|params|body)|['"]\s*\+)/,
    description: 'Potential open redirect vulnerability',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '601',
    cwe: '601'
  },
  resourceLeak: {
    pattern: /fs\.readFileSync\s*\(|fs\.writeFileSync\s*\(/,
    description: 'Potential resource leak due to synchronous file operations',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '399',
    cwe: '399'
  },

  // Session Management Patterns
  sessionFixation: {
    pattern: /req\.session\.id\s*=\s*req\.(query|params|body)|session\.id\s*=\s*req\.(query|params|body)/,
    description: 'Potential session fixation vulnerability allowing attacker to set session id',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '384',
    cwe: '384'
  },
  insecureSessionStorage: {
    pattern: /session\.cookie\s*=\s*[^;]+secure\s*:\s*false/i,
    description: 'Insecure session storage without secure flags',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '925',
    cwe: '925'
  },

  // Server-Side Request Forgery Patterns
  ssrfVulnerability: {
    pattern: /((axios|fetch|request)\s*\().*(req\.query|req\.params|req\.body)/,
    description: 'Potential SSRF vulnerability from user-supplied input in request calls',
    severity: 'CRITICAL',
    category: patternCategories.SSRF,
    subcategory: '918',
    cwe: '918'
  },

  // API Security Patterns
  insecureAPISetup: {
    pattern: /app\.use\s*\(\s*['"]\/api['"],\s*[^)]+\)/,
    description: 'Potential insecure API setup without proper authentication middleware',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '921',
    cwe: '921'
  },
  jwtInURL: {
    pattern: /jwt=.*[&?]/,
    description: 'JWT token present in URL instead of headers',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '922',
    cwe: '922'
  },
  tokenInURL: {
    pattern: /token=.*[&?]/,
    description: 'Authentication token present in URL parameters',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '923',
    cwe: '923'
  },
  badRateLimit: {
    pattern: /rateLimit\s*:\s*(?:\d+|\{[^}]+\})/,
    description: 'Potentially weak rate limiting configuration in API setup',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '924',
    cwe: '924'
  },
  missingCORS: {
    pattern: /app\.use\s*\(\s*['"]\/api['"],\s*cors\s*\(\s*\)\s*\)/,
    description: 'Missing or misconfigured CORS in API setup',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '925',
    cwe: '925'
  },
  insecureMiddleware: {
    pattern: /app\.use\s*\(\s*[^,]+,\s*[^,]+,\s*[^)]+\)/,
    description: 'Insecure middleware setup allowing unauthorized access',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '926',
    cwe: '926'
  },

  // Dependency Management Patterns
  vulnerableDependency: {
    pattern: /"dependencies"\s*:\s*{[^}]*}/, // Simplistic pattern; enhanced in scanner logic
    description: 'Vulnerable dependencies detected in package.json',
    severity: 'HIGH',
    category: patternCategories.DEPENDENCY_MANAGEMENT,
    subcategory: '925',
    cwe: '925'
  },
  outdatedDependency: {
    pattern: /"dependencies"\s*:\s*{[^}]*}/, // Simplistic pattern; enhanced in scanner logic
    description: 'Outdated dependencies detected in package.json',
    severity: 'MEDIUM',
    category: patternCategories.DEPENDENCY_MANAGEMENT,
    subcategory: '926',
    cwe: '926'
  }
};
// Recommendations
export const recommendations = {
  evalExecution: {
    recommendation: `
**Why it Matters**: Using \`eval()\` or the Function constructor can allow malicious 
code to run in your application, leading to data theft or system compromise.

**What to Do**:
1. **Avoid Dynamic Code**: Use safer alternatives (e.g., \`JSON.parse\` for JSON data).
2. **Sanitize Input**: If dynamic evaluation is unavoidable, carefully whitelist 
   valid inputs and reject anything unexpected.

**Example**:
Instead of:

\`\`\`javascript
eval(userInput);
\`\`\`

Do:

\`\`\`javascript
const parsed = JSON.parse(userInput); // with validation
\`\`\`

    `,
    references: [
      {
        title: 'CWE-95: Eval Injection',
        url: 'https://cwe.mitre.org/data/definitions/95.html'
      }
    ],
    cwe: '95'
  },

  commandInjection: {
    recommendation: `
**Why it Matters**: Command injection vulnerabilities let attackers run arbitrary
system commands, possibly taking full control of the server.

**What to Do**:
1. **Use \`execFile\`**: Prefer \`child_process.execFile()\` or \`spawn()\` with arguments, 
   instead of \`exec()\`.
2. **Validate User Input**: Reject or escape special characters (like ";", "&", "|").

**Example**:
Instead of:
\`\`\`javascript
exec('ls -la ' + userInput);
\`\`\`
Do:
\`\`\`javascript
execFile('ls', ['-la', userInput], callback);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-77: Command Injection',
        url: 'https://cwe.mitre.org/data/definitions/77.html'
      }
    ],
    cwe: '77'
  },

  missingAuth: {
    recommendation: `
**Why it Matters**: Skipping authentication leaves data wide open.

**What to Do**:
1. **Require Auth** on all sensitive endpoints.
2. **Use a robust auth system** or library.

**Example**:
Instead of:
\`\`\`javascript
app.get("/admin", (req, res) => { ... });
\`\`\`
Do:
\`\`\`javascript
app.get("/admin", requireAuth, (req, res) => { ... });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-306: Missing Authentication',
        url: 'https://cwe.mitre.org/data/definitions/306.html'
      }
    ],
    cwe: '306'
  },

  hardcodedCreds: {
    recommendation: `
**Why it Matters**: Hardcoded credentials can be easily discovered and exploited.

**What to Do**:
1. **Use Environment Variables** or secret managers.
2. **Rotate Credentials** if leaked.
3. **Implement Secret Detection** hooks to block commits with secrets.

**Example**:
Instead of:
\`\`\`javascript
const password = "supersecret123";
\`\`\`
Do:
\`\`\`javascript
const password = process.env.DB_PASSWORD;
\`\`\`
    `,
    references: [
      {
        title: 'CWE-798: Use of Hard-coded Credentials',
        url: 'https://cwe.mitre.org/data/definitions/798.html'
      },
      {
        title: 'OWASP Secure Configuration Guide',
        url: 'https://owasp.org/www-project-secure-configuration-guide/'
      }
    ],
    cwe: '798'
  },

  sqlInjection: {
    recommendation: `
**Why it Matters**: SQL injection can lead to database breaches or 
full system compromise.

**What to Do**:
1. **Use Parameterized Statements** / prepared statements or an ORM.
2. **Never concatenate** user input directly into queries.

**Example**:
Instead of:
\`\`\`javascript
db.query("SELECT * FROM users WHERE id = " + userId);
\`\`\`
Do:
\`\`\`javascript
db.query("SELECT * FROM users WHERE id = ?", [userId]);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-89: SQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/89.html'
      },
      {
        title: 'OWASP SQL Injection Prevention',
        url: 'https://owasp.org/www-community/attacks/SQL_Injection'
      }
    ],
    cwe: '89'
  },

  xssVulnerability: {
    recommendation: `
**Why it Matters**: XSS allows attackers to run arbitrary scripts in the victim’s browser.

**What to Do**:
1. **Escape/Encode Output** or use a safe templating framework.
2. **Enable CSP** to reduce script injection vectors.

**Example**:
Instead of:
\`\`\`javascript
element.innerHTML = userInput;
\`\`\`
Do:
\`\`\`javascript
element.textContent = userInput;
\`\`\`
    `,
    references: [
      {
        title: 'CWE-79: Cross-site Scripting',
        url: 'https://cwe.mitre.org/data/definitions/79.html'
      },
      {
        title: 'OWASP XSS Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '79'
  },

  noSqlInjection: {
    recommendation: `
**Why it Matters**: NoSQL databases can still be compromised by malicious queries 
if user input is not properly sanitized.

**What to Do**:
1. **Use Parameterized Queries** or query builders.
2. **Validate User Input** for suspicious patterns like "$where" or "$regex".

**Example**:
Instead of:
\`\`\`javascript
db.users.find({ $where: "this.password === '" + userInput + "'" });
\`\`\`
Do:
\`\`\`javascript
db.users.find({ password: userSuppliedPassword });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-943: Improper Neutralization of Special Elements in Data Query Logic',
        url: 'https://cwe.mitre.org/data/definitions/943.html'
      }
    ],
    cwe: '943'
  },

  weakCrypto: {
    recommendation: `
**Why it Matters**: MD5 and SHA-1 are cryptographically weak.

**What to Do**:
1. **Use stronger hashes** like SHA-256 or better.
2. **Implement key management** and rotate keys often.

**Example**:
Instead of:
\`\`\`javascript
crypto.createHash('md5').update(data).digest('hex');
\`\`\`
Do:
\`\`\`javascript
crypto.createHash('sha256').update(data).digest('hex');
\`\`\`
    `,
    references: [
      {
        title: 'CWE-326: Inadequate Encryption Strength',
        url: 'https://cwe.mitre.org/data/definitions/326.html'
      }
    ],
    cwe: '326'
  },

  sensitiveErrorInfo: {
    recommendation: `
**Why it Matters**: Exposing full error messages or stack traces can reveal 
sensitive info to attackers.

**What to Do**:
1. **Log Detailed Errors Privately**, show generic messages publicly.
2. **Sanitize Outputs**.

**Example**:
Instead of:
\`\`\`javascript
res.send({ stack: err.stack });
\`\`\`
Do:
\`\`\`javascript
console.error(err);
res.status(500).send({ error: "Something went wrong" });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-209: Information Exposure Through an Error Message',
        url: 'https://cwe.mitre.org/data/definitions/209.html'
      }
    ],
    cwe: '209'
  },

  pathTraversal: {
    recommendation: `
**Why it Matters**: Attackers can manipulate file paths to access system files 
outside intended directories.

**What to Do**:
1. **Use \`path.resolve()\`** or similar to normalize paths.
2. **Block ".." sequences** in user-supplied filenames.

**Example**:
Instead of:
\`\`\`javascript
fs.readFileSync("../" + userInput);
\`\`\`
Do:
\`\`\`javascript
const safePath = path.resolve("/safe/base", userInput);
fs.readFileSync(safePath);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-23: Relative Path Traversal',
        url: 'https://cwe.mitre.org/data/definitions/23.html'
      }
    ],
    cwe: '23'
  },

  openRedirect: {
    recommendation: `
**Why it Matters**: Open redirects can trick users into visiting malicious websites.

**What to Do**:
1. **Use a Whitelist** for allowed redirect domains.
2. **Show a confirmation** or fallback to a safe page if invalid.

**Example**:
Instead of:
\`\`\`javascript
res.redirect(req.query.url);
\`\`\`
Do:
\`\`\`javascript
if (allowedUrls.includes(req.query.url)) res.redirect(req.query.url);
else res.redirect("/error");
\`\`\`
    `,
    references: [
      {
        title: 'CWE-601: URL Redirection to Untrusted Site',
        url: 'https://cwe.mitre.org/data/definitions/601.html'
      }
    ],
    cwe: '601'
  },

  weakPasswordHash: {
    recommendation: `
**Why it Matters**: Using weak password hashes (low cost factor) 
makes brute-forcing easier.

**What to Do**:
1. **Use Strong Hashing** like \`bcrypt≥12\`, scrypt, or Argon2.
2. **Use Salts/Pepper**.

**Example**:
Instead of:
\`\`\`javascript
bcrypt.hash(password, 10);
\`\`\`
Do:
\`\`\`javascript
bcrypt.hash(password, 12);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-916: Use of Password Hash With Insufficient Computational Effort',
        url: 'https://cwe.mitre.org/data/definitions/916.html'
      }
    ],
    cwe: '916'
  },

  ssrfVulnerability: {
    recommendation: `
**Why it Matters**: SSRF can let an attacker pivot to internal services.

**What to Do**:
1. **Validate Outbound URLs** against an allowlist.
2. **Block internal IP ranges**.

**Example**:
Instead of:
\`\`\`javascript
axios.get(req.query.url);
\`\`\`
Do:
\`\`\`javascript
if (isSafeUrl(req.query.url)) axios.get(req.query.url);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-918: Server-Side Request Forgery',
        url: 'https://cwe.mitre.org/data/definitions/918.html'
      },
      {
        title: 'OWASP SSRF Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '918'
  },

  sessionFixation: {
    recommendation: `
**Why it Matters**: Session fixation lets attackers set or reuse a session ID.

**What to Do**:
1. **Regenerate Session** on login.
2. **Avoid session IDs in URLs**, use secure cookies instead.

**Example**:
Instead of:
\`\`\`javascript
req.session.id = req.query.sessionId;
\`\`\`
Do:
\`\`\`javascript
req.session.regenerate(() => { ... });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-384: Session Fixation',
        url: 'https://cwe.mitre.org/data/definitions/384.html'
      }
    ],
    cwe: '384'
  },

  insecureAPISetup: {
    recommendation: `
**Why it Matters**: Insecure API setup without proper authentication middleware can expose your endpoints to unauthorized access and potential attacks.

**What to Do**:
1. **Implement Authentication Middleware**: Ensure that all API routes are protected with robust authentication mechanisms.
2. **Use Role-Based Access Control (RBAC)**: Define and enforce user roles and permissions.
3. **Validate API Inputs**: Sanitize and validate all incoming data to prevent injection attacks.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', apiHandler);
\`\`\`
Do:
\`\`\`javascript
app.use('/api', authenticateUser, apiHandler);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-921: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/921.html'
      },
      {
        title: 'OWASP Authentication Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
      }
    ],
    cwe: '921'
  },

  jwtInURL: {
    recommendation: `
**Why it Matters**: JWT tokens in URLs can be exposed through browser history, logs, or referer headers, leading to token theft and unauthorized access.

**What to Do**:
1. **Transmit JWTs via Headers**: Use the \`Authorization\` header to send JWTs securely.
2. **Avoid Including Tokens in URLs**: Refrain from appending tokens as query parameters.
3. **Implement Secure Storage**: Store tokens in secure, HTTP-only cookies or secure storage mechanisms.

**Example**:
Instead of:
\`\`\`javascript
axios.get(\`https://api.example.com/data?jwt=\${token}\`);
\`\`\`
Do:
\`\`\`javascript
axios.get('https://api.example.com/data', {
  headers: { Authorization: \`Bearer \${token}\` }
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-922: Link Following Without Verification of Destination',
        url: 'https://cwe.mitre.org/data/definitions/922.html'
      },
      {
        title: 'OWASP JWT Security Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html'
      }
    ],
    cwe: '922'
  },



  tokenInURL: {
    recommendation: `
**Why it Matters**: Authentication tokens in URLs can be intercepted or exposed through logs, browser history, or referer headers, leading to unauthorized access.

**What to Do**:
1. **Use Secure Headers**: Transmit tokens via the \`Authorization\` header.
2. **Avoid URL Parameters for Sensitive Data**: Do not include tokens or sensitive information in URLs.
3. **Implement HTTPS**: Ensure all communications are encrypted to protect token transmission.

**Example**:
Instead of:
\`\`\`javascript
fetch(\`http://example.com/api?token=\${authToken}\`);
\`\`\`
Do:
\`\`\`javascript
fetch('https://example.com/api', {
  headers: { Authorization: \`Bearer \${authToken}\` }
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-922: Link Following Without Verification of Destination',
        url: 'https://cwe.mitre.org/data/definitions/922.html'
      },
      {
        title: 'OWASP JWT Security Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html'
      }
    ],
    cwe: '923'
  },

  badRateLimit: {
    recommendation: `
**Why it Matters**: Weak rate limiting configurations can be exploited for brute-force attacks, denial-of-service (DoS), or abuse of API endpoints.

**What to Do**:
1. **Implement Strong Rate Limiting**: Define sensible limits on the number of requests per user/IP.
2. **Use Distributed Rate Limiting**: Ensure rate limits are enforced across multiple servers or instances.
3. **Provide Feedback**: Inform users when rate limits are exceeded without revealing sensitive information.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
\`\`\`
Do:
\`\`\`javascript
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
}));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-924: Improper Enforcement of Business Rules',
        url: 'https://cwe.mitre.org/data/definitions/924.html'
      },
      {
        title: 'OWASP Rate Limiting Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html'
      }
    ],
    cwe: '924'
  },

  missingCORS: {
    recommendation: `
**Why it Matters**: Improper or missing Cross-Origin Resource Sharing (CORS) configurations can allow unauthorized domains to interact with your APIs, leading to data leaks or unauthorized actions.

**What to Do**:
1. **Configure CORS Properly**: Define allowed origins, methods, and headers explicitly.
2. **Restrict Access**: Limit CORS to trusted domains only.
3. **Use Credentials Wisely**: Ensure that credentials are only sent to trusted origins.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', cors());
\`\`\`
Do:
\`\`\`javascript
app.use('/api', cors({
  origin: ['https://trusted-domain.com'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-925: Use of Existing, Secure Components with Known Vulnerabilities',
        url: 'https://cwe.mitre.org/data/definitions/925.html'
      },
      {
        title: 'OWASP CORS Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html'
      }
    ],
    cwe: '925'
  },

  insecureMiddleware: {
    recommendation: `
**Why it Matters**: Insecure middleware setups can inadvertently expose sensitive endpoints or allow unauthorized access, undermining the security of your APIs.

**What to Do**:
1. **Ensure Authentication Middleware is Properly Placed**: Protect sensitive routes by placing authentication middleware before route handlers.
2. **Limit Middleware Scope**: Apply middleware only to necessary routes to minimize exposure.
3. **Regularly Review Middleware Configurations**: Audit middleware settings to ensure they adhere to security best practices.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', someMiddleware, apiHandler);
\`\`\`
Do:
\`\`\`javascript
app.use('/api', authenticateUser, someMiddleware, apiHandler);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-926: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/926.html'
      },
      {
        title: 'OWASP Secure Headers Project',
        url: 'https://owasp.org/www-project-secure-headers/'
      }
    ],
    cwe: '926'
  },
  // InsecureTransmission
insecureTransmission: {
  recommendation: `
**Why it Matters**: Transmitting data over HTTP (cleartext) can allow attackers to intercept and read sensitive information.

**What to Do**:
1. **Use HTTPS**: Always transmit data over TLS/SSL.
2. **Enforce Strict Transport Security (HSTS)**: Configure your server to require HTTPS connections.
3. **Avoid Sensitive Data in Query Params**: Even over HTTPS, be cautious with tokens or credentials in URLs.

**Example**:
Instead of:
\`\`\`javascript
fetch('http://example.com/api', { ... });
\`\`\`
Do:
\`\`\`javascript
fetch('https://example.com/api', { ... });
\`\`\`
  `,
  references: [
    {
      title: 'CWE-319: Cleartext Transmission of Sensitive Information',
      url: 'https://cwe.mitre.org/data/definitions/319.html'
    },
    {
      title: 'OWASP Transport Layer Protection Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'
    }
  ],
  cwe: '319'
},

// ResourceLeak
resourceLeak: {
  recommendation: `
**Why it Matters**: Synchronous file I/O (or unclosed resources) can cause memory or resource leaks, degrade performance, and potentially block the event loop.

**What to Do**:
1. **Use Asynchronous Methods**: Prefer async I/O when reading/writing files to avoid blocking.
2. **Properly Close Resources**: Close file handles, database connections, and sockets.
3. **Handle Errors**: Ensure error handling paths also close or release resources.

**Example**:
Instead of:
\`\`\`javascript
fs.readFileSync('someLargeFile.txt');
\`\`\`
Do:
\`\`\`javascript
fs.readFile('someLargeFile.txt', (err, data) => {
  if (err) throw err;
  // handle data
});
\`\`\`
  `,
  references: [
    {
      title: 'CWE-399: Resource Management Errors',
      url: 'https://cwe.mitre.org/data/definitions/399.html'
    }
  ],
  cwe: '399'
},

// SensitiveData
sensitiveData: {
  recommendation: `
**Why it Matters**: Exposing or mishandling passwords, tokens, or other sensitive data can lead to unauthorized access and data breaches.

**What to Do**:
1. **Use Strong Encryption**: Encrypt sensitive fields at rest (e.g., database) and in transit (HTTPS).
2. **Limit Access**: Store sensitive data in environment variables or secure vaults.
3. **Redact Logs**: Never log raw credentials or tokens.

**Example**:
Instead of:
\`\`\`javascript
const password = "supersecret";
logger.info(\`User password is: \${password}\`);
\`\`\`
Do:
\`\`\`javascript
const password = process.env.DB_PASSWORD;
logger.info("User password retrieved securely");
\`\`\`
  `,
  references: [
    {
      title: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
      url: 'https://cwe.mitre.org/data/definitions/200.html'
    },
    {
      title: 'OWASP Top 10: Sensitive Data Exposure',
      url: 'https://owasp.org/Top10/A03_2021-Sensitive_Data_Exposure/'
    }
  ],
  cwe: '200'
},

// UnsanitizedInputUsage
unsanitizedInputUsage: {
  recommendation: `
**Why it Matters**: Using raw, unsanitized user input in sensitive operations can allow attackers to manipulate configuration, perform injections, or escalate privileges.

**What to Do**:
1. **Validate Input**: Strictly check that input matches expected formats (e.g., regex, schemas).
2. **Sanitize or Escape**: Remove or escape special characters before using them in file paths, queries, etc.
3. **Use Safe APIs**: For queries or commands, prefer parameterized methods or built-in safety functions.

**Example**:
Instead of:
\`\`\`javascript
config.dbHost = req.body.dbHost;
\`\`\`
Do:
\`\`\`javascript
if (isValidHostname(req.body.dbHost)) {
  config.dbHost = sanitizeHostname(req.body.dbHost);
}
\`\`\`
  `,
  references: [
    {
      title: 'CWE-932: Insecure Mechanism for Updating or Upgrading Software',
      url: 'https://cwe.mitre.org/data/definitions/932.html'
    },
    {
      title: 'OWASP Input Validation Cheat Sheet',
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
    }
  ],
  cwe: '932'
},

// BufferIssue
bufferIssue: {
  recommendation: `
**Why it Matters**: Using unsafe buffer allocation (like \`Buffer.allocUnsafe\` or the deprecated \`new Buffer\`) can lead to uninitialized memory leaks or potential buffer overflows.

**What to Do**:
1. **Use Safe Buffer Methods**: Prefer \`Buffer.alloc\` or \`Buffer.from\` instead of unsafe variants.
2. **Validate Data Length**: Ensure you don’t write more data than the buffer’s capacity.
3. **Avoid Deprecated Constructors**: \`new Buffer()\` is deprecated since Node.js 6.

**Example**:
Instead of:
\`\`\`javascript
const unsafeBuf = new Buffer(10); // or Buffer.allocUnsafe(10)
\`\`\`
Do:
\`\`\`javascript
const safeBuf = Buffer.alloc(10); // zero-filled
\`\`\`
  `,
  references: [
    {
      title: 'CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer',
      url: 'https://cwe.mitre.org/data/definitions/119.html'
    },
    {
      title: 'Node.js Buffer Documentation',
      url: 'https://nodejs.org/api/buffer.html'
    }
  ],
  cwe: '119'
},

  vulnerableDependency: {
    recommendation: `
**Why it Matters**: Vulnerable dependencies can be exploited to compromise your application, leading to data breaches or unauthorized access.

**What to Do**:
1. **Update Dependencies**: Regularly update dependencies to their latest secure versions.
2. **Use Automated Tools**: Integrate tools like \`npm audit\`, \`Snyk\`, or \`Dependabot\` to monitor and remediate vulnerabilities.
3. **Limit Dependencies**: Only include necessary dependencies to reduce the attack surface.

**Example**:
Instead of:
\`\`\`json
"dependencies": {
  "lodash": "^4.17.15"
}
\`\`\`
Do:
\`\`\`json
"dependencies": {
  "lodash": "^4.17.21"
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-925: Use of Existing, Secure Components with Known Vulnerabilities',
        url: 'https://cwe.mitre.org/data/definitions/925.html'
      },
      {
        title: 'OWASP Dependency-Check',
        url: 'https://owasp.org/www-project-dependency-check/'
      }
    ],
    cwe: '925'
  },

  insecureCryptoUsage: {
    recommendation: `
  **Why it Matters**: Using deprecated cryptographic functions (like \`crypto.createCipher\` or \`crypto.createDecipher\`) can result in insecure encryption. These older APIs lack modern security features (e.g., authenticated encryption), and may allow attackers to decrypt or tamper with data.
  
  **What to Do**:
  1. **Use \`createCipheriv\`** or similar modern APIs: These allow specifying the algorithm, key, and IV explicitly.
  2. **Choose a Strong Cipher**: Use AES-256-GCM or another well-reviewed cipher rather than older, weaker algorithms.
  3. **Implement Key Management**: Ensure keys and IVs are generated/stored securely.
  
  **Example**:
  Instead of:
  \`\`\`javascript
  const cipher = crypto.createCipher('aes192', 'somePasswordKey');
  \`\`\`
  Do:
  \`\`\`javascript
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, ivBuffer);
  \`\`\`
    `,
    references: [
      {
        title: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
        url: 'https://cwe.mitre.org/data/definitions/327.html'
      },
      {
        title: 'Node.js Crypto Documentation',
        url: 'https://nodejs.org/api/crypto.html'
      }
    ],
    cwe: '927'
  },
  
  insecureDirectObjectRef: {
    recommendation: `
  **Why it Matters**: Insecure Direct Object References (IDOR) allow attackers to manipulate parameters (like user IDs, document IDs, etc.) to access data they shouldn't. Without proper authorization checks, any user can potentially read or modify another user's information.
  
  **What to Do**:
  1. **Enforce Authorization**: Validate that the current user is allowed to access the requested resource. 
  2. **Use Indirect References**: Instead of exposing real IDs, map them to temporary tokens or hashed identifiers.
  3. **Check Ownership**: Always confirm the resource belongs to (or is permissible for) the authenticated user.
  
  **Example**:
  Instead of:
  \`\`\`javascript
  app.get('/document/:id', (req, res) => {
    return db.getDocument(req.params.id); // No checks
  });
  \`\`\`
  Do:
  \`\`\`javascript
  app.get('/document/:id', (req, res) => {
    if (!userCanAccess(req.user, req.params.id)) {
      return res.status(403).send('Forbidden');
    }
    return db.getDocument(req.params.id);
  });
  \`\`\`
    `,
    references: [
      {
        title: 'CWE-639: Insecure Direct Object Reference (IDOR)',
        url: 'https://cwe.mitre.org/data/definitions/639.html'
      },
      {
        title: 'OWASP Broken Access Control',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      }
    ],
    cwe: '639'
  },
  memoryLeak: {
    recommendation: `
  **Why it Matters**: Timers, intervals, or event listeners can cause memory leaks if references to large objects or resources are never cleared. Over time, this can degrade performance or cause application crashes.
  
  **What to Do**:
  1. **Track and Clear Intervals**: Store the return from \`setInterval\` and call \`clearInterval\` when you no longer need it.
  2. **Limit Scope**: Avoid capturing large objects in timer callbacks that persist references.
  3. **Check for Orphaned Listeners**: Remove event listeners or intervals in cleanup logic (e.g., when a component unmounts in React or a route finishes in Express).
  
  **Example**:
  Instead of:
  \`\`\`javascript
  setInterval(() => {
    // Some operation holding onto a big object
  }, 1000);
  \`\`\`
  Do:
  \`\`\`javascript
  const intervalId = setInterval(() => {
    // Perform the required operation
  }, 1000);
  
  // Later, when done:
  clearInterval(intervalId);
  \`\`\`
    `,
    references: [
      {
        title: 'CWE-401: Missing Release of Memory after Effective Lifetime',
        url: 'https://cwe.mitre.org/data/definitions/401.html'
      },
      {
        title: 'MDN: setInterval() Documentation',
        url: 'https://developer.mozilla.org/docs/Web/API/WindowOrWorkerGlobalScope/setInterval'
      }
    ],
    cwe: '401'
  },
  

  outdatedDependency: {
    recommendation: `
**Why it Matters**: Outdated dependencies may lack the latest security patches, exposing your application to known vulnerabilities.

**What to Do**:
1. **Regularly Review Dependencies**: Periodically check and update dependencies to their latest versions.
2. **Automate Updates**: Use tools like \`npm outdated\`, \`Dependabot\`, or \`Renovate\` to automate dependency updates.
3. **Test After Updates**: Ensure that updates do not break application functionality by implementing comprehensive testing.

**Example**:
Instead of:
\`\`\`json
"dependencies": {
  "express": "^4.16.0"
}
\`\`\`
Do:
\`\`\`json
"dependencies": {
  "express": "^4.18.2"
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-926: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/926.html'
      },
      {
        title: 'OWASP Dependency-Check',
        url: 'https://owasp.org/www-project-dependency-check/'
      }
    ],
    cwe: '926'
  }
};
