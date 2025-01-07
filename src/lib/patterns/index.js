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
// Categories

// Refined Patterns
export const patterns = {
  // Execution Patterns
  evalExecution: {
    /**
     *  - Anchored for “eval” or “new Function”
     *  - Ignores partial matches like “myEvalFunc”
     */
    pattern: /(^|[^.\w])(eval|new\s+Function)\s*\(/,
    description: 'Dangerous code execution via eval() or Function constructor',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '95',
    cwe: '95'
  },

  commandInjection: {
    /**
     *  - Looks for child_process.exec/spawn/fork/execFile or bare "exec("
     *  - Avoids partial matches like “executor” or “executeStuff()”
     */
    pattern: /\b(child_process\.(?:exec|spawn|execFile|fork)\s*\(|exec\s*\()/,
    description: 'Potential command injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '77',
    cwe: '77'
  },

  // Authentication Patterns
  missingAuth: {
    /**
     *  - Uses word boundaries (\b) to avoid partial matches like "authfalseEnabled"
     */
    pattern: /\bauthentication\s*:\s*false\b|\bauth\s*:\s*false\b|\bnoAuth\s*:\s*true\b|\bskipAuth\b/i,
    description: 'Authentication bypass or missing authentication',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '306',
    cwe: '306'
  },
  hardcodedCreds: {
    /**
     *  - Requires a boundary (\b) around "password|secret|key|token|credential"
     *  - Then captures : or = 
     *  - Followed by a quoted string
     *  - Case-insensitive
     */
    pattern: /\b(password|secret|key|token|credential)s?\b\s*[:=]\s*['"][^'"]+['"]/i,
    description: 'Hardcoded credentials detected',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '798',
    cwe: '798'
  },

  // Injection Patterns
  sqlInjection: {
    /**
     *  - Ensures we catch “SELECT/INSERT/UPDATE/DELETE” as a whole word (\b)
     *  - Must have FROM/INTO/WHERE somewhere after
     *  - Then a quote or question mark that might indicate direct input injection
     */
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE)\b.*\b(FROM|INTO|WHERE)\b.*(\?|'|")/i,
    description: 'Potential SQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89',
    cwe: '89'
  },
  xssVulnerability: {
    /**
     *  - Matches direct writes to innerHTML/outerHTML, document.write, or jQuery .html()
     *  - This tries to avoid false positives by requiring a boundary (\b)
     */
    pattern: /\b(innerHTML|outerHTML)\b\s*=|\bdocument\.write\s*\(|\$\(\S*\)\.html\s*\(/,
    description: 'Cross-site scripting vulnerability',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79',
    cwe: '79'
  },
  noSqlInjection: {
    /**
     *  - Looks for $where or usage of $regex in a .find() query
     *  - Could be expanded to check for other NoSQL operators too
     */
    pattern: /\b\$where\s*:\s*['"]|\.find\s*\(\s*{[^}]*\$regex/i,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '943',
    cwe: '943'
  },

  // Cryptography Patterns
  weakCrypto: {
    /**
     *  - Also handles possible variations like 'sha-1' or "sha1"
     */
    pattern: /crypto\.createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\)/i,
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
    /**
     *  - Matches new Buffer() or Buffer.allocUnsafe()
     *  - Negative lookbehind can be used if we want to exclude comments, but
     *    that often gets too tricky in plain regex scanning
     */
    pattern: /\bBuffer\.(allocUnsafe|from)\s*\(|\bnew\s+Buffer\s*\(/,
    // Alternatively: /(?<!\/\/.*)(?<!\/\*.*)(Buffer\.allocUnsafe\(|new\s+Buffer\()/
    description: 'Unsafe buffer allocation',
    severity: 'HIGH',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '119',
    cwe: '119'
  },
  memoryLeak: {
    /**
     *  - Looks for setInterval/setTimeout with arguments that might be storing big references
     *  - This is still broad, but at least ensures a second argument is present 
     */
    pattern: /\b(setInterval|setTimeout)\s*\([^,]+,\s*\d+\s*\)/,
    description: 'Potential memory leak in timer/interval',
    severity: 'MEDIUM',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '401',
    cwe: '401'
  },

  // Data Protection Patterns
  sensitiveData: {
    pattern: /\b(password|token|secret|key|credential)s?\b\s*=\s*[^;]+/i,
    description: 'Sensitive data exposure',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '200',
    cwe: '200'
  },
  insecureTransmission: {
    /**
     *  - Looks for “http://” that’s not localhost/127.0.0.1
     *  - Negative lookahead for “localhost|127.0.0.1”
     */
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/,
    description: 'Potential insecure data transmission',
    severity: 'MEDIUM',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '319',
    cwe: '319'
  },

  // Error Handling Patterns
  sensitiveErrorInfo: {
    /**
     *  - Checks if we catch(...) { console.log(...) or res.send(...err...) 
     *  - You might still get partial matches, but it’s better than nothing
     */
    pattern: /catch\s*\([^)]*\)\s*{\s*(?:console\.(?:log|error)|res\.(?:json|send))\s*\([^)]*(?:err|error)/,
    description: 'Potential sensitive information in error messages',
    severity: 'MEDIUM',
    category: patternCategories.ERROR_HANDLING,
    subcategory: '209',
    cwe: '209'
  },

  // Access Control Patterns
  insecureDirectObjectRef: {
    /**
     *  - This looks for e.g. “userId = req.query.userId”
     *  - You could expand if you want to detect “.body.userId” etc.
     */
    pattern: /\b(?:user|account|file|document)Id\s*=\s*(?:params|query|body|req)\.[a-zA-Z_][a-zA-Z0-9_]*/,
    description: 'Potential Insecure Direct Object Reference (IDOR)',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '639',
    cwe: '639'
  },
  improperAuthorizationChecks: {
    /**
     *  - Checking “if (!req.user.isAdmin || !req.user.hasPermission) ...” 
     *    can be ambiguous. This is a heuristic at best.
     */
    pattern: /if\s*\(\s*(!?req\.user\.isAdmin\s*|\s*!req\.user\.hasPermission)/,
    description: 'Improper authorization checks allowing unauthorized access',
    severity: 'CRITICAL',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '306',
    cwe: '306'
  },

  // Input Validation Patterns
  pathTraversal: {
    /**
     *  - Looks for ../ or ..\ sequences to flag potential path traversal
     *  - You might want to ensure it’s not in a comment, etc.
     */
    pattern: /(?:\.\.\/|\.\.\\|\.\.[/\\])[^/\\]*/,
    description: 'Potential path traversal vulnerability',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '23',
    cwe: '23'
  },
  unsanitizedInputUsage: {
    /**
     *  - Looks for usage of user input in config or env
     *  - Could be refined more (like checking .body input specifically)
     */
    pattern: /\b(process\.env\.[^\s;]+|config\.[a-zA-Z0-9_]+)\s*=\s*req\.[a-zA-Z0-9_]+/,
    description: 'Unsanitized user input used in sensitive operations',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '932',
    cwe: '932'
  },

  // Resource Management Patterns
  openRedirect: {
    /**
     *  - Looks for “res.redirect = req.query/params” or “location.href = ...”
     *  - Minimal bounding to reduce false positives
     */
    pattern: /(?:\bres\.redirect|\bwindow\.location|\blocation\.href)\s*=\s*(?:req\.(?:query|params|body)|['"]\s*\+)/,
    description: 'Potential open redirect vulnerability',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '601',
    cwe: '601'
  },
  resourceLeak: {
    /**
     *  - Matching usage of sync file operations that could tie up resources
     *  - Still simplistic, but better than nothing
     */
    pattern: /\bfs\.(?:readFileSync|writeFileSync)\s*\(/,
    description: 'Potential resource leak due to synchronous file operations',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '399',
    cwe: '399'
  },

  // Session Management Patterns
  sessionFixation: {
    pattern: /\breq\.session\.id\s*=\s*req\.(query|params|body)|\bsession\.id\s*=\s*req\.(query|params|body)/,
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
    /**
     *  - Looks for axios/fetch/request( ) with user input from req.query/params/body
     *  - Could still catch some false positives, but helps identify SSRF-ish code
     */
    pattern: /\b(?:axios|fetch|request)\s*\(\s*.*req\.(?:query|params|body)/,
    description: 'Potential SSRF vulnerability from user-supplied input in request calls',
    severity: 'CRITICAL',
    category: patternCategories.SSRF,
    subcategory: '918',
    cwe: '918'
  },

  // API Security Patterns
  insecureAPISetup: {
    /**
     *  - Looks for app.use('/api', ...) with no mention of "auth" or "authenticate"
     *  - Minimal check, might need more advanced analysis for real coverage
     */
    pattern: /app\.use\s*\(\s*['"]\/api['"],\s*[^)]*(?!auth)/,
    description: 'Potential insecure API setup without proper authentication middleware',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '921',
    cwe: '921'
  },
  jwtInURL: {
    pattern: /\bjwt=.*[&?]/,
    description: 'JWT token present in URL instead of headers',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '922',
    cwe: '922'
  },
  tokenInURL: {
    pattern: /\btoken=.*[&?]/,
    description: 'Authentication token present in URL parameters',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '923',
    cwe: '923'
  },
  badRateLimit: {
    /**
     *  - Looks for “rateLimit: <value>” or “rateLimit: { ... }”
     *  - Could false-positive if your code has a custom variable named “rateLimit”
     */
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
    /**
     *  - Very broad heuristic for “app.use( something, something, something )”
     *  - Could catch normal multi-middleware usage. Might refine further.
     */
    pattern: /app\.use\s*\(\s*[^,]+,\s*[^,]+,\s*[^)]+\)/,
    description: 'Insecure middleware setup allowing unauthorized access',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '926',
    cwe: '926'
  },

  // Dependency Management Patterns
  vulnerableDependency: {
    /**
     *  - Still a naive approach. You might parse package.json in detail
     */
    pattern: /"dependencies"\s*:\s*{[^}]*}/,
    description: 'Vulnerable dependencies detected in package.json',
    severity: 'HIGH',
    category: patternCategories.DEPENDENCY_MANAGEMENT,
    subcategory: '925',
    cwe: '925'
  },
  outdatedDependency: {
    pattern: /"dependencies"\s*:\s*{[^}]*}/,
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
      },
      {
        title: 'CAPEC-242: Code Injection',
        url: 'https://capec.mitre.org/data/definitions/242.html'
      },
      {
        title: 'CVE-2017-5638: (Apache Struts OGNL Injection Example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638'
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
      },
      {
        title: 'CAPEC-248: Command Injection',
        url: 'https://capec.mitre.org/data/definitions/248.html'
      },
      {
        title: 'CVE-2014-6271: Shellshock (Bash Command Injection)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271'
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
      },
      {
        title: 'CAPEC-115: Authentication Bypass',
        url: 'https://capec.mitre.org/data/definitions/115.html'
      },
      {
        title: 'CVE-2020-26890 (Example of missing auth in IoT devices)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26890'
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
        title: 'CAPEC-630: Embedding Credentials in Software',
        url: 'https://capec.mitre.org/data/definitions/630.html'
      },
      {
        title: 'CVE-2017-12794 (HP Printers with hardcoded creds)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12794'
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
        title: 'CAPEC-66: SQL Injection',
        url: 'https://capec.mitre.org/data/definitions/66.html'
      },
      {
        title: 'CVE-2019-11510 (Pulse Secure SQL injection)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510'
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
        title: 'CAPEC-86: Cross-Site Scripting',
        url: 'https://capec.mitre.org/data/definitions/86.html'
      },
      {
        title: 'CVE-2022-24675 (Example XSS in WordPress Plugin)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24675'
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
      },
      {
        title: 'CAPEC-400: Data Manipulation via Injection',
        url: 'https://capec.mitre.org/data/definitions/400.html'
      },
      {
        title: 'CVE-2020-7610 (NoSQL Injection in npm package mongoose)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7610'
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
      },
      {
        title: 'CAPEC-246: Cryptanalysis',
        url: 'https://capec.mitre.org/data/definitions/246.html'
      },
      {
        title: 'CVE-2021-23840 (OpenSSL MD5 collision issue)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840'
      }
    ],
    cwe: '326'
  },

  insecureCryptoUsage: {
    recommendation: `
**Why it Matters**: Using deprecated cryptographic functions (like \`crypto.createCipher\` or \`crypto.createDecipher\`) can result in insecure encryption. These older APIs lack modern security features and may allow attackers to decrypt or tamper with data.

**What to Do**:
1. **Use \`createCipheriv\`**: This allows specifying the algorithm, key, and IV explicitly.
2. **Choose a Strong Cipher**: Use AES-256-GCM or another well-reviewed cipher.
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
        title: 'CAPEC-644: Use of a Broken or Risky Cryptographic Algorithm',
        url: 'https://capec.mitre.org/data/definitions/644.html'
      },
      {
        title: 'CVE-2021-3449 (OpenSSL improper decryption handling)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449'
      }
    ],
    cwe: '927'
  },

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
        title: 'CAPEC-100: Buffer Overflow',
        url: 'https://capec.mitre.org/data/definitions/100.html'
      },
      {
        title: 'CVE-2018-1000001 (Buffer overflow example in various apps)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001'
      }
    ],
    cwe: '119'
  },

  memoryLeak: {
    recommendation: `
**Why it Matters**: Timers, intervals, or event listeners can cause memory leaks if references to large objects or resources are never cleared. Over time, this can degrade performance or cause application crashes.

**What to Do**:
1. **Track and Clear Intervals**: Store the return from \`setInterval\` and call \`clearInterval\` when you no longer need it.
2. **Limit Scope**: Avoid capturing large objects in timer callbacks that persist references.
3. **Check for Orphaned Listeners**: Remove event listeners or intervals in cleanup logic.

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
        title: 'CAPEC-129: Resource Depletion',
        url: 'https://capec.mitre.org/data/definitions/129.html'
      },
      {
        title: 'CVE-2019-19078 (Linux Kernel memory leak example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19078'
      }
    ],
    cwe: '401'
  },

  sensitiveData: {
    recommendation: `
**Why it Matters**: Exposing or mishandling passwords, tokens, or other sensitive data can lead to unauthorized access and data breaches.

**What to Do**:
1. **Use Strong Encryption**: Encrypt sensitive fields at rest and in transit.
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
        title: 'CWE-200: Exposure of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/200.html'
      },
      {
        title: 'CAPEC-118: Data Interception Attacks',
        url: 'https://capec.mitre.org/data/definitions/118.html'
      },
      {
        title: 'CVE-2024-2731 (Example of sensitive info exposure)',
        url: 'https://www.cve.org/cveRecord?id=CVE-2024-2731'
      }
    ],
    cwe: '200'
  },

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
        title: 'CAPEC-9: Man-in-the-Middle Attack',
        url: 'https://capec.mitre.org/data/definitions/9.html'
      },
      {
        title: 'CVE-2020-12066 (HTTP-based data leak example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12066'
      }
    ],
    cwe: '319'
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
      },
      {
        title: 'CAPEC-125: Exception or Error Message Analysis',
        url: 'https://capec.mitre.org/data/definitions/125.html'
      },
      {
        title: 'CVE-2018-5210 (Sensitive error exposure in NodeBB)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5210'
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
      },
      {
        title: 'CAPEC-126: Path Traversal',
        url: 'https://capec.mitre.org/data/definitions/126.html'
      },
      {
        title: 'CVE-2021-22986 (Path traversal in F5 BIG-IP)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22986'
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
if (allowedUrls.includes(req.query.url)) {
  res.redirect(req.query.url);
} else {
  res.redirect("/error");
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-601: URL Redirection to Untrusted Site',
        url: 'https://cwe.mitre.org/data/definitions/601.html'
      },
      {
        title: 'CAPEC-107: Redirect to Alternate Site',
        url: 'https://capec.mitre.org/data/definitions/107.html'
      },
      {
        title: 'CVE-2019-16527 (Example open redirect in Jenkins)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16527'
      }
    ],
    cwe: '601'
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
        title: 'CAPEC-651: Server-Side Request Forgery (SSRF)',
        url: 'https://capec.mitre.org/data/definitions/651.html'
      },
      {
        title: 'OWASP SSRF Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
      },
      {
        title: 'CVE-2021-3129 (Laravel SSRF example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3129'
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
      },
      {
        title: 'CAPEC-61: Session Fixation',
        url: 'https://capec.mitre.org/data/definitions/61.html'
      },
      {
        title: 'CVE-2015-0262 (Session fixation in Apache Shiro)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0262'
      }
    ],
    cwe: '384'
  },

  insecureAPISetup: {
    recommendation: `
**Why it Matters**: Insecure API setup without proper authentication middleware can expose your endpoints to unauthorized access and potential attacks.

**What to Do**:
1. **Implement Authentication Middleware**: Protect all API routes with robust authentication.
2. **Use Role-Based Access Control (RBAC)**: Enforce user roles and permissions.
3. **Validate API Inputs**: Sanitize all incoming data.

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
        title: 'CWE-921: Improper Restriction of Excessive Authentication Attempts',
        url: 'https://cwe.mitre.org/data/definitions/921.html'
      },
      {
        title: 'CAPEC-115: Authentication Bypass',
        url: 'https://capec.mitre.org/data/definitions/115.html'
      },
      {
        title: 'CVE-2022-22965 (Spring4Shell) – though primarily an RCE, it also highlights insecure API endpoints',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965'
      }
    ],
    cwe: '921'
  },

  jwtInURL: {
    recommendation: `
**Why it Matters**: JWT tokens in URLs can be exposed through browser history, logs, or referer headers, leading to token theft and unauthorized access.

**What to Do**:
1. **Transmit JWTs via Headers**: Use the \`Authorization\` header to send JWTs securely.
2. **Avoid Including Tokens in URLs**.
3. **Implement Secure Storage**: Store tokens in secure, HTTP-only cookies or secure storage.

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
        title: 'CWE-922: Insecure Storage of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/922.html'
      },
      {
        title: 'CAPEC-593: Session Hijacking',
        url: 'https://capec.mitre.org/data/definitions/593.html'
      },
      {
        title: 'CVE-2018-0114 (JWT in URL example in Cisco devices)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0114'
      }
    ],
    cwe: '922'
  },

  tokenInURL: {
    recommendation: `
**Why it Matters**: Authentication tokens in URLs can be intercepted or exposed through logs, browser history, or referer headers, leading to unauthorized access.

**What to Do**:
1. **Use Secure Headers**: Transmit tokens via the \`Authorization\` header.
2. **Avoid URL Parameters for Sensitive Data**.
3. **Implement HTTPS**: Ensure all communications are encrypted.

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
        title: 'CWE-923: Improper Restriction of Referer Header or Similar Data in HTTP Request',
        url: 'https://cwe.mitre.org/data/definitions/923.html'
      },
      {
        title: 'CAPEC-593: Session Hijacking',
        url: 'https://capec.mitre.org/data/definitions/593.html'
      },
      {
        title: 'CVE-2022-0527 (Sensitive token in URL example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0527'
      }
    ],
    cwe: '923'
  },

  badRateLimit: {
    recommendation: `
**Why it Matters**: Weak rate limiting configurations can be exploited for brute-force attacks, denial-of-service (DoS), or abuse of API endpoints.

**What to Do**:
1. **Implement Strong Rate Limiting**: Define sensible limits on the number of requests per user/IP.
2. **Use Distributed Rate Limiting** if you have multiple servers.
3. **Provide Feedback**: Inform users when rate limits are exceeded.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
\`\`\`
Do:
\`\`\`javascript
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: "Too many requests from this IP, please try again later."
}));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-924: Improper Enforcement of Message or Data Structure',
        url: 'https://cwe.mitre.org/data/definitions/924.html'
      },
      {
        title: 'CAPEC-129: Resource Depletion (DoS)',
        url: 'https://capec.mitre.org/data/definitions/129.html'
      },
      {
        title: 'CVE-2019-9512 (Rate limiting bypass in HTTP/2)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9512'
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
        title: 'CWE-925: Improper Verification of Trusted Source',
        url: 'https://cwe.mitre.org/data/definitions/925.html'
      },
      {
        title: 'CAPEC-353: Cross-Domain Attack',
        url: 'https://capec.mitre.org/data/definitions/353.html'
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
1. **Ensure Authentication Middleware is Properly Placed**: Protect sensitive routes before route handlers.
2. **Limit Middleware Scope**: Apply middleware only to necessary routes.
3. **Regularly Review Middleware Configurations**.

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
        title: 'CAPEC-224: Modification of Configuration/Environment',
        url: 'https://capec.mitre.org/data/definitions/224.html'
      },
      {
        title: 'OWASP Secure Headers Project',
        url: 'https://owasp.org/www-project-secure-headers/'
      }
    ],
    cwe: '926'
  },

  resourceLeak: {
    recommendation: `
**Why it Matters**: Synchronous file I/O (or unclosed resources) can cause memory or resource leaks, degrade performance, and potentially block the event loop.

**What to Do**:
1. **Use Asynchronous Methods**: Prefer async I/O when reading/writing files.
2. **Properly Close Resources**: Close file handles, DB connections, etc.
3. **Handle Errors**: Ensure error paths also close or release resources.

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
      },
      {
        title: 'CAPEC-119: Excessive Allocation',
        url: 'https://capec.mitre.org/data/definitions/119.html'
      },
      {
        title: 'CVE-2021-22555 (Linux Kernel resource management issue)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22555'
      }
    ],
    cwe: '399'
  },

  unsanitizedInputUsage: {
    recommendation: `
**Why it Matters**: Using raw, unsanitized user input in sensitive operations can allow attackers to manipulate configuration, perform injections, or escalate privileges.

**What to Do**:
1. **Validate Input**: Strictly check that input matches expected formats.
2. **Sanitize or Escape**: Remove or escape special characters before using them in file paths, queries, etc.
3. **Use Safe APIs**: For queries or commands, prefer parameterized methods or safe libraries.

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
        title: 'CAPEC-400: Manipulation of Data Structures',
        url: 'https://capec.mitre.org/data/definitions/400.html'
      },
      {
        title: 'OWASP Input Validation Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
      }
    ],
    cwe: '932'
  },

  insecureDirectObjectRef: {
    recommendation: `
**Why it Matters**: Insecure Direct Object References (IDOR) allow attackers to manipulate parameters (like user IDs, file IDs, etc.) to access data they shouldn't. Without proper authorization checks, any user can read or modify another user's data.

**What to Do**:
1. **Enforce Authorization**: Validate that the current user is allowed to access the requested resource.
2. **Use Indirect References**: Instead of exposing real IDs, map them to tokens or hashed identifiers.
3. **Check Ownership**: Always confirm the resource belongs to the authenticated user.

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
        title: 'CAPEC-714: IDOR Attack Pattern',
        url: 'https://capec.mitre.org/data/definitions/714.html'
      },
      {
        title: 'CVE-2018-11235 (Git IDOR example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11235'
      }
    ],
    cwe: '639'
  },

  vulnerableDependency: {
    recommendation: `
**Why it Matters**: Vulnerable dependencies can be exploited to compromise your application, leading to data breaches or unauthorized access.

**What to Do**:
1. **Update Dependencies**: Regularly update dependencies to secure versions.
2. **Use Automated Tools**: \`npm audit\`, \`Snyk\`, or \`Dependabot\` to monitor vulnerabilities.
3. **Limit Dependencies**: Only include what you really need.

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
        title: 'CWE-925: Use of Vulnerable Components',
        url: 'https://cwe.mitre.org/data/definitions/925.html'
      },
      {
        title: 'CAPEC-659: Exploitation of Third-Party Vulnerability',
        url: 'https://capec.mitre.org/data/definitions/659.html'
      },
      {
        title: 'CVE-2021-23337 (lodash vulnerability example)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337'
      }
    ],
    cwe: '925'
  },

  outdatedDependency: {
    recommendation: `
**Why it Matters**: Outdated dependencies may lack the latest security patches, exposing your application to known vulnerabilities.

**What to Do**:
1. **Regularly Review Dependencies**: Periodically check and update dependencies.
2. **Automate Updates**: Use \`npm outdated\`, \`Dependabot\`, or \`Renovate\`.
3. **Test After Updates**: Use comprehensive tests to ensure no breakage.

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
        title: 'CWE-926: Improper Authorization / Use of Outdated Components',
        url: 'https://cwe.mitre.org/data/definitions/926.html'
      },
      {
        title: 'OWASP Dependency-Check',
        url: 'https://owasp.org/www-project-dependency-check/'
      },
      {
        title: 'CVE-2018-18074 (Express outdated version vulnerability)',
        url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18074'
      }
    ],
    cwe: '926'
  },
  improperAuthorizationChecks: {
    recommendation: `
  **Why it Matters**: If authorization checks are too simplistic or missing in critical paths, attackers may access privileged functions or data without proper permissions.
  
  **What to Do**:
  1. **Enforce Role/Permission Checks**: Ensure every privileged route or function verifies user roles/permissions explicitly.
  2. **Use a Centralized Authorization Mechanism**: Avoid ad-hoc checks scattered across the code; rely on a well-tested library or framework feature.
  3. **Validate Ownership**: For operations on user-specific data (like editing a profile), confirm the authenticated user owns the resource.
  
  **Example**:
  Instead of:
  \`\`\`javascript
  if (req.user) {
    doAdminStuff(); // No role/permission check
  }
  \`\`\`
  Use:
  \`\`\`json
  if (req.user && req.user.role === 'admin') {
    doAdminStuff();
  }
  \`\`\`
    `,
    references: [
      {
        title: 'CWE-306: Missing Authentication for Critical Function',
        url: 'https://cwe.mitre.org/data/definitions/306.html'
      },
      {
        title: 'CAPEC-115: Authentication Bypass',
        url: 'https://capec.mitre.org/data/definitions/115.html'
      },
      {
        title: 'OWASP Broken Access Control',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      }
    ],
    cwe: '306'
  }  
};
