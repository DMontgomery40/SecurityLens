import React from 'react';

// Add category structure
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

  // New Categories
  SSRF: '918',                 // Server-Side Request Forgery
  SESSION_MANAGEMENT: '384'    // Session management issues
};

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  if (!results) return null;

  const { findings = [], summary = {} } = results;
  
  return (
    <div className="mt-8">
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">Scan Results</h2>
        
        {/* Summary Section */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-red-50 p-4 rounded-lg">
            <div className="font-semibold text-red-700">Critical</div>
            <div className="text-2xl">{summary.criticalIssues || 0}</div>
          </div>
          <div className="bg-orange-50 p-4 rounded-lg">
            <div className="font-semibold text-orange-700">High</div>
            <div className="text-2xl">{summary.highIssues || 0}</div>
          </div>
          <div className="bg-yellow-50 p-4 rounded-lg">
            <div className="font-semibold text-yellow-700">Medium</div>
            <div className="text-2xl">{summary.mediumIssues || 0}</div>
          </div>
          <div className="bg-blue-50 p-4 rounded-lg">
            <div className="font-semibold text-blue-700">Low</div>
            <div className="text-2xl">{summary.lowIssues || 0}</div>
          </div>
        </div>

        {/* Cache Notice */}
        {usedCache && (
          <div className="mb-4 flex items-center justify-between bg-blue-50 p-4 rounded-lg">
            <span className="text-blue-700">
              ⚡ Results loaded from cache
            </span>
            <button
              onClick={onRefreshRequest}
              disabled={scanning}
              className={`px-4 py-2 rounded text-sm ${
                scanning
                  ? 'bg-gray-300 cursor-not-allowed'
                  : 'bg-blue-500 hover:bg-blue-600 text-white'
              }`}
            >
              {scanning ? 'Refreshing...' : 'Refresh Scan'}
            </button>
          </div>
        )}

        {/* Findings List */}
        {findings.length > 0 ? (
          <div className="space-y-4">
            {findings.map((finding, index) => {
              const recommendation = recommendations[finding.type];
              
              return (
                <div key={index} className="border rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-semibold text-lg">{finding.description}</h3>
                      <div className="text-sm text-gray-500">
                        Found in: {Object.keys(finding.allLineNumbers).join(', ')}
                      </div>
                    </div>
                    <div className={`
                      px-3 py-1 rounded-full text-sm font-medium
                      ${finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                        finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                        finding.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-blue-100 text-blue-800'}
                    `}>
                      {finding.severity}
                    </div>
                  </div>
                  
                  {recommendation && (
                    <div className="mt-4">
                      <div className="prose prose-sm max-w-none">
                        <div dangerouslySetInnerHTML={{ 
                          __html: recommendation.recommendation
                            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                            .replace(/\n/g, '<br />') 
                        }} />
                      </div>
                      
                      {recommendation.references && (
                        <div className="mt-4">
                          <h4 className="font-medium text-sm mb-2">References:</h4>
                          <ul className="list-disc pl-5 space-y-1">
                            {recommendation.references.map((ref, idx) => (
                              <li key={idx}>
                                <a 
                                  href={ref.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-sm text-blue-600 hover:underline"
                                >
                                  {ref.title}
                                </a>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500">
            No vulnerabilities found
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanResults;

// Modify core patterns structure
export const corePatterns = {
  // CRITICAL EXECUTION VULNERABILITIES
  evalExecution: {
    pattern: /eval\s*\([^)]*\)|new\s+Function\s*\(/,
    description: 'Dangerous code execution via eval() or Function constructor',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '95'  // Eval injection
  },
  commandInjection: {
    pattern: /child_process\.exec\s*\(|\.exec\s*\(|\.spawn\s*\(/,
    description: 'Potential command injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '77'  // Command injection
  },

  // AUTHENTICATION VULNERABILITIES
  missingAuth: {
    pattern: /authentication:\s*false|auth:\s*false|noAuth:\s*true|skipAuth/i,
    description: 'Authentication bypass or missing authentication',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '306'  // Missing authentication
  },
  hardcodedCreds: {
    pattern: /(password|secret|key|token|credential)s?\s*[:=]\s*['"`][^'"`]+['"`]/i,
    description: 'Hardcoded credentials detected',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '798'  // Use of hard-coded credentials
  },

  // INJECTION VULNERABILITIES
  sqlInjection: {
    pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
    description: 'Potential SQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89'  // SQL injection
  },
  xssVulnerability: {
    pattern: /innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|\$\(.*\)\.html\s*\(/,
    description: 'Cross-site scripting vulnerability',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79'  // XSS
  },

  // MEMORY & BUFFER VULNERABILITIES
  bufferIssue: {
    pattern: /Buffer\.allocUnsafe\s*\(|new\s+Buffer\s*\(/,
    description: 'Unsafe buffer allocation',
    severity: 'HIGH',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '119'  // Buffer overflow
  },
  memoryLeak: {
    pattern: /(setInterval|setTimeout)\s*\([^,]+,[^)]+\)/,
    description: 'Potential memory leak in timer/interval',
    severity: 'MEDIUM',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '401'  // Memory leak
  },

  // DATA PROTECTION VULNERABILITIES
  sensitiveData: {
    pattern: /(password|token|secret|key|credential)s?\s*=\s*[^;]+/i,
    description: 'Sensitive data exposure',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '200'  // Information exposure
  },
  insecureTransmission: {
    pattern: /https?:\/\/(?!localhost|127\.0\.0\.1)/,
    description: 'Potential insecure data transmission',
    severity: 'MEDIUM',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '319'  // Cleartext transmission
  }
};

// Enhanced patterns with additional security checks
export const enhancedPatterns = {
  // CRITICAL EXECUTION VULNERABILITIES
  deserializationVuln: {
    pattern: /JSON\.parse\s*\((?![^)]*JSON\.stringify)|unserialize\s*\(/,
    description: 'Unsafe deserialization of user input',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '502'  // Deserialization of Untrusted Data
  },
    
  // ACCESS CONTROL VULNERABILITIES
  insecureDirectObjectRef: {
    pattern: /\b(?:user|account|file|document)Id\s*=\s*(?:params|query|body|req)\.[a-zA-Z_][a-zA-Z0-9_]*/,
    description: 'Potential Insecure Direct Object Reference (IDOR)',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '639'  // Authorization Bypass Through User-Controlled Key
  },
    
  // INJECTION VULNERABILITIES
  noSqlInjection: {
    pattern: /\$where\s*:\s*['"`]|\.find\s*\(\s*{[^}]*\$regex/,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '943'  // NoSQL Injection
  },
    
  // CRYPTO ISSUES
  weakCrypto: {
    pattern: /crypto\.createHash\s*\(\s*['"`]md5['"`]\)|crypto\.createHash\s*\(\s*['"`]sha1['"`]\)/,
    description: 'Use of weak cryptographic hash function',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_ISSUES,
    subcategory: '326'  // Inadequate Encryption Strength
  },
    
  // ERROR HANDLING
  sensitiveErrorInfo: {
    pattern: /catch\s*\([^)]*\)\s*{\s*(?:console\.(?:log|error)|res\.(?:json|send))\s*\([^)]*(?:err|error)/,
    description: 'Potential sensitive information in error messages',
    severity: 'MEDIUM',
    category: patternCategories.ERROR_HANDLING,
    subcategory: '209'  // Information Exposure Through Error Message
  },
    
  // INPUT VALIDATION
  pathTraversal: {
    pattern: /(?:\.\.\/|\.\.\\|\.\.[/\\])[^/\\]*/,
    description: 'Potential path traversal vulnerability',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '23'  // Path Traversal
  },
    
  // RESOURCE MANAGEMENT
  openRedirect: {
    pattern: /(?:res\.redirect|window\.location|location\.href)\s*=\s*(?:req\.(?:query|params|body)|['"`]\s*\+)/,
    description: 'Potential open redirect vulnerability',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '601'  // URL Redirection to Untrusted Site
  },
    
  // AUTHENTICATION
  weakPasswordHash: {
    pattern: /\.hash\s*\(\s*['"`](?:md5|sha1)['"`]\)|bcrypt\.hash\s*\([^,]*,\s*(?:[1-9]|10)\s*\)/,
    description: 'Weak password hashing detected',
    severity: 'HIGH',
    category: patternCategories.AUTHENTICATION,
    subcategory: '916'  // Use of Password Hash With Insufficient Computational Effort
  },

  // New Patterns

  // SERVER-SIDE REQUEST FORGERY (SSRF)
  ssrfVulnerability: {
    pattern: /((axios|fetch|request)\s*\().*(req\.query|req\.params|req\.body)/,
    description: 'Potential SSRF vulnerability from user-supplied input in request calls',
    severity: 'CRITICAL',
    category: patternCategories.SSRF,
    subcategory: '918'  // Server-Side Request Forgery
  },

  // SESSION MANAGEMENT
  sessionFixation: {
    pattern: /req\.session\.id\s*=\s*req\.(query|params|body)|session\.id\s*=\s*req\.(query|params|body)/,
    description: 'Potential session fixation vulnerability allowing attacker to set session id',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '384'  // Session Fixation
  }
};

// Thorough & visually enhanced recommendations
export const recommendations = {
  // CRITICAL EXECUTION

  evalExecution: {
    recommendation: `
      **Why it Matters**: Using eval() or the Function constructor can allow malicious 
      code to run in your application, leading to data theft or system compromise.

      **What to Do**:
      1. **Avoid Dynamic Code**: Use safer alternatives (e.g., JSON.parse for JSON data).
      2. **Sanitize Input**: If dynamic evaluation is unavoidable, carefully whitelist 
         valid inputs and reject anything unexpected.

      **Example**: 
      Instead of:
        eval(userInput);
      Do:
        const parsed = JSON.parse(userInput); // with validation
    `,
    references: [
      {
        title: 'CWE-95: Eval Injection',
        url: 'https://cwe.mitre.org/data/definitions/95.html',
        description: 'Comprehensive guide on eval injection vulnerabilities'
      }
    ],
    cwe: '95'
  },

  commandInjection: {
    recommendation: `
      **Why it Matters**: Command injection vulnerabilities let attackers run arbitrary
      system commands, possibly taking full control of the server.

      **What to Do**:
      1. **Use execFile**: Prefer child_process.execFile() or spawn() with arguments, 
         instead of exec().
      2. **Validate User Input**: Reject or escape special characters (like ";", "&", "|").

      **Example**:
      Instead of:
        exec('ls -la ' + userInput);
      Do:
        execFile('ls', ['-la', userInput], callback);
    `,
    references: [
      {
        title: 'CWE-77: Command Injection',
        url: 'https://cwe.mitre.org/data/definitions/77.html',
        description: 'Details on preventing command injection attacks'
      }
    ],
    cwe: '77'
  },

  deserializationVuln: {
    recommendation: `
      **Why it Matters**: Deserializing untrusted data can allow attackers to instantiate 
      malicious objects or execute arbitrary code.

      **What to Do**:
      1. **Validate and Sanitize**: Check all incoming data before parsing or deserializing.
      2. **Use Safe Formats**: Prefer well-defined data structures like protocol buffers, 
         or use JSON with strict schema validation.

      **Example**: 
      Instead of:
        unserialize(userInput);
      Do:
        // Validate userInput, then parse safe JSON
        const safeData = JSON.parse(userInput);
    `,
    references: [
      {
        title: 'CWE-502: Deserialization of Untrusted Data',
        url: 'https://cwe.mitre.org/data/definitions/502.html',
        description: 'Understanding deserialization vulnerabilities'
      }
    ],
    cwe: '502'
  },

  // ACCESS CONTROL

  insecureDirectObjectRef: {
    recommendation: `
      **Why it Matters**: Attackers can manipulate object IDs (e.g., userId, fileId) to 
      gain unauthorized access to sensitive resources.

      **What to Do**:
      1. **Enforce Access Checks**: Use server-side verification to confirm the requesting 
         user has permission to the requested resource.
      2. **Use Opaque References**: Avoid exposing direct IDs in URLs or user-visible areas.

      **Example**:
      Instead of:
        const document = Documents.find(req.query.docId);
      Do:
        const doc = Documents.find(req.query.docId);
        if (doc.owner !== currentUser.id) throw 'Unauthorized';
    `,
    references: [
      {
        title: 'CWE-639: Authorization Bypass Through User-Controlled Key',
        url: 'https://cwe.mitre.org/data/definitions/639.html',
        description: 'Understanding IDOR vulnerabilities'
      }
    ],
    cwe: '639'
  },

  // INJECTION

  noSqlInjection: {
    recommendation: `
      **Why it Matters**: NoSQL databases can still be compromised by malicious queries 
      if user input is not properly sanitized.

      **What to Do**:
      1. **Use Parameterized Queries**: Use query builders or parameter bindings 
         that separate query structure from data.
      2. **Validate User Input**: Check for suspicious patterns like "$where" 
         or "$regex" when building dynamic queries.

      **Example**:
      Instead of:
        db.users.find({ $where: "this.password === '" + userInput + "'" });
      Do:
        db.users.find({ password: userSuppliedPassword });
    `,
    references: [
      {
        title: 'CWE-943: Improper Neutralization of Special Elements in Data Query Logic',
        url: 'https://cwe.mitre.org/data/definitions/943.html',
        description: 'Understanding NoSQL injection'
      }
    ],
    cwe: '943'
  },

  sqlInjection: {
    recommendation: `
      **Why it Matters**: SQL injection can lead to database breaches, data loss, or 
      complete system compromise.

      **What to Do**:
      1. **Use Parameterized Statements**: Rely on prepared statements or ORM methods.
      2. **Never String-Concatenate**: Do not inline user input directly into SQL queries.

      **Example**:
      Instead of:
        db.query("SELECT * FROM users WHERE id = " + userId);
      Do:
        db.query("SELECT * FROM users WHERE id = ?", [userId]);
    `,
    references: [
      {
        title: 'CWE-89: SQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/89.html',
        description: 'Understanding SQL injection vulnerabilities'
      },
      {
        title: 'OWASP SQL Injection Prevention',
        url: 'https://owasp.org/www-community/attacks/SQL_Injection',
        description: 'Comprehensive guide to preventing SQL injection'
      }
    ],
    cwe: '89'
  },

  xssVulnerability: {
    recommendation: `
      **Why it Matters**: XSS (Cross-Site Scripting) allows attackers to run arbitrary 
      scripts in the victim’s browser, stealing data or credentials.

      **What to Do**:
      1. **Escape/Encode Output**: Use proper output encoding or templating frameworks.
      2. **Avoid Direct DOM Manipulation**: Use frameworks with built-in XSS protection 
         (e.g., Angular, React).
      3. **Enable CSP**: Content Security Policy can help limit script injection.

      **Example**:
      Instead of:
        element.innerHTML = userInput;
      Do:
        element.textContent = userInput;
        // or use a safe templating library
    `,
    references: [
      {
        title: 'CWE-79: Cross-site Scripting',
        url: 'https://cwe.mitre.org/data/definitions/79.html',
        description: 'Understanding XSS vulnerabilities'
      },
      {
        title: 'OWASP XSS Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        description: 'Detailed XSS prevention techniques'
      }
    ],
    cwe: '79'
  },

  // CRYPTO ISSUES

  weakCrypto: {
    recommendation: `
      **Why it Matters**: MD5 and SHA-1 are considered cryptographically weak, making it 
      easier for attackers to generate collisions or brute force hashed data.

      **What to Do**:
      1. **Use Strong Hashes**: Upgrade to SHA-256 or better, along with salt and pepper 
         if appropriate.
      2. **Implement Key Management**: Rotate keys frequently and store them securely.

      **Example**:
      Instead of:
        crypto.createHash('md5').update(data).digest('hex');
      Do:
        crypto.createHash('sha256').update(data).digest('hex');
    `,
    references: [
      {
        title: 'CWE-326: Inadequate Encryption Strength',
        url: 'https://cwe.mitre.org/data/definitions/326.html',
        description: 'Understanding cryptographic weaknesses'
      }
    ],
    cwe: '326'
  },

  // ERROR HANDLING

  sensitiveErrorInfo: {
    recommendation: `
      **Why it Matters**: Exposing full error messages or stack traces can reveal 
      sensitive details (file paths, server configs, tokens) to attackers.

      **What to Do**:
      1. **Log Privately**: Keep detailed errors in server logs, not user-facing responses.
      2. **Sanitize Outputs**: Return only a simple error message or code to the client.

      **Example**:
      Instead of:
        res.send({ stack: err.stack });
      Do:
        console.error(err);
        res.status(500).send({ error: "An unexpected error occurred." });
    `,
    references: [
      {
        title: 'CWE-209: Information Exposure Through an Error Message',
        url: 'https://cwe.mitre.org/data/definitions/209.html',
        description: 'Proper error handling practices'
      }
    ],
    cwe: '209'
  },

  // INPUT VALIDATION

  pathTraversal: {
    recommendation: `
      **Why it Matters**: Attackers can manipulate file paths to access system files 
      outside intended directories, leading to sensitive data exposure or code execution.

      **What to Do**:
      1. **Canonicalize Paths**: Use path.resolve() or similar to ensure final paths 
         remain within allowed directories.
      2. **Filter Dangerous Patterns**: Block sequences like "../" in user-supplied filenames.

      **Example**:
      Instead of:
        fs.readFileSync("../" + userInput);
      Do:
        const safePath = path.resolve(BASE_PATH, userInput);
        fs.readFileSync(safePath);
    `,
    references: [
      {
        title: 'CWE-23: Relative Path Traversal',
        url: 'https://cwe.mitre.org/data/definitions/23.html',
        description: 'Understanding path traversal attacks'
      }
    ],
    cwe: '23'
  },

  // RESOURCE MANAGEMENT

  openRedirect: {
    recommendation: `
      **Why it Matters**: Open redirects can trick users into visiting malicious websites 
      and facilitate phishing attacks.

      **What to Do**:
      1. **Use a Whitelist**: Only allow redirects to known/trusted URLs.
      2. **Confirm Intent**: Show the user a confirmation page or message before redirecting.

      **Example**:
      Instead of:
        res.redirect(req.query.returnUrl);
      Do:
        const allowed = ["https://trusteddomain.com"];
        if (allowed.includes(req.query.returnUrl)) {
          res.redirect(req.query.returnUrl);
        } else {
          res.redirect("/error");
        }
    `,
    references: [
      {
        title: 'CWE-601: URL Redirection to Untrusted Site',
        url: 'https://cwe.mitre.org/data/definitions/601.html',
        description: 'Understanding open redirect vulnerabilities'
      }
    ],
    cwe: '601'
  },

  // AUTHENTICATION

  weakPasswordHash: {
    recommendation: `
      **Why it Matters**: Using weak or insufficiently costly hash functions makes it easier 
      for attackers to brute-force passwords.

      **What to Do**:
      1. **Use Strong Password Hashing**: bcrypt (with a work factor ≥ 12), scrypt, PBKDF2, 
         or Argon2.
      2. **Salt & Pepper**: Ensure unique salts per password, and consider an application-wide 
         pepper stored securely.

      **Example**:
      Instead of:
        bcrypt.hash(password, 10);
      Do:
        bcrypt.hash(password, 12); // or more
    `,
    references: [
      {
        title: 'CWE-916: Use of Password Hash With Insufficient Computational Effort',
        url: 'https://cwe.mitre.org/data/definitions/916.html',
        description: 'Understanding password hashing security'
      }
    ],
    cwe: '916'
  },

  missingAuth: {
    recommendation: `
      **Why it Matters**: Skipping or disabling authentication can open your app 
      to unauthorized access.

      **What to Do**:
      1. **Always Require Auth**: Secure all endpoints handling sensitive data 
         with authentication.
      2. **Use Robust Frameworks**: Leverage libraries or frameworks that handle 
         auth out of the box.

      **Example**:
      Instead of:
        app.get("/admin", (req, res) => {...}); 
      Do:
        app.get("/admin", requireAuth, (req, res) => {...});
    `,
    references: [
      {
        title: 'CWE-306: Missing Authentication',
        url: 'https://cwe.mitre.org/data/definitions/306.html',
        description: 'Understanding missing authentication vulnerabilities'
      }
    ],
    cwe: '306'
  },

  hardcodedCreds: {
    recommendation: `
      **Why it Matters**: Hardcoded credentials in source code can be found by 
      attackers, giving direct access to privileged resources.

      **What to Do**:
      1. **Use Environment Variables**: Store secrets in env files or secret management 
         systems (e.g., Vault, AWS Secrets Manager).
      2. **Rotate Credentials**: If credentials leak, rotate them immediately 
         and remove from code history.

      **Example**:
      Instead of:
        const password = "supersecret123";
      Do:
        const password = process.env.DB_PASSWORD;
    `,
    references: [
      {
        title: 'CWE-798: Use of Hard-coded Credentials',
        url: 'https://cwe.mitre.org/data/definitions/798.html',
        description: 'Risks of hardcoded credentials'
      },
      {
        title: 'OWASP Secure Configuration Guide',
        url: 'https://owasp.org/www-project-secure-configuration-guide/',
        description: 'Best practices for credential management'
      }
    ],
    cwe: '798'
  },

  // MEMORY/BUFFER

  bufferIssue: {
    recommendation: `
      **Why it Matters**: Using Buffer.allocUnsafe() or new Buffer() without length checks 
      can lead to uninitialized memory exposure or buffer overflows.

      **What to Do**:
      1. **Use Secure Methods**: Use Buffer.alloc() instead of Buffer.allocUnsafe().
      2. **Initialize & Validate**: Zero out or sanitize newly allocated buffers 
         and validate input lengths.

      **Example**:
      Instead of:
        let buff = new Buffer(size);
      Do:
        let buff = Buffer.alloc(size);
    `,
    references: [
      {
        title: 'CWE-119: Buffer Overflow',
        url: 'https://cwe.mitre.org/data/definitions/119.html',
        description: 'Understanding buffer overflow vulnerabilities'
      },
      {
        title: 'Node.js Buffer API Security',
        url: 'https://nodejs.org/api/buffer.html#buffer_buffer_alloc_size_fill_encoding',
        description: 'Official Node.js documentation on secure buffer usage'
      }
    ],
    cwe: '119'
  },

  memoryLeak: {
    recommendation: `
      **Why it Matters**: Memory leaks degrade application performance over time, 
      possibly causing crashes or excessive resource consumption.

      **What to Do**:
      1. **Clean Up**: Track and clear intervals/timeouts when they're no longer needed.
      2. **Use Lifecycle Hooks**: In front-end frameworks, unmount or remove event 
         listeners, intervals, or timeouts properly.

      **Example**:
      Instead of:
        setInterval(() => doSomething(), 1000);
      Do:
        const intervalId = setInterval(() => doSomething(), 1000);
        // later
        clearInterval(intervalId);
    `,
    references: [
      {
        title: 'CWE-401: Memory Leak',
        url: 'https://cwe.mitre.org/data/definitions/401.html',
        description: 'Understanding memory leak vulnerabilities'
      }
    ],
    cwe: '401'
  },

  // DATA PROTECTION

  sensitiveData: {
    recommendation: `
      **Why it Matters**: Logging or exposing credentials or other sensitive data 
      can lead to account compromise if logs or code are leaked.

      **What to Do**:
      1. **Mask or Omit**: Never log full passwords, tokens, or keys. 
         Store only hashed or partial data as needed.
      2. **Encrypt at Rest**: If storing credentials, use strong encryption 
         and secure key management.

      **Example**:
      Instead of:
        console.log("Password:", password);
      Do:
        // Only log that a password was used, or hide it entirely
        console.log("User password received.");
    `,
    references: [
      {
        title: 'CWE-200: Information Exposure',
        url: 'https://cwe.mitre.org/data/definitions/200.html',
        description: 'Understanding information exposure risks'
      },
      {
        title: 'OWASP Sensitive Data Exposure',
        url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
        description: 'OWASP guide on protecting sensitive data'
      }
    ],
    cwe: '200'
  },

  insecureTransmission: {
    recommendation: `
      **Why it Matters**: Sending data (passwords, tokens) over HTTP can be intercepted 
      by attackers, leading to credential theft or session hijacking.

      **What to Do**:
      1. **Use HTTPS/TLS**: Secure all endpoints with TLS certificates.
      2. **Enforce HSTS**: Implement HTTP Strict Transport Security to prevent 
         downgrade attacks.

      **Example**:
      Instead of:
        fetch('http://payment.example.com');
      Do:
        fetch('https://payment.example.com');
    `,
    references: [
      {
        title: 'CWE-319: Cleartext Transmission',
        url: 'https://cwe.mitre.org/data/definitions/319.html',
        description: 'Risks of cleartext data transmission'
      },
      {
        title: 'OWASP Transport Layer Protection',
        url: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet',
        description: 'Best practices for secure data transmission'
      }
    ],
    cwe: '319'
  },

  // NEW VULNERABILITIES

  ssrfVulnerability: {
    recommendation: `
      **Why it Matters**: SSRF can let an attacker make internal network calls, 
      access sensitive internal resources, or exploit internal services.

      **What to Do**:
      1. **Use URL Validation**: Check the domain against an allowlist. 
         Block internal IP ranges, link-local addresses, etc.
      2. **Limit HTTP Methods**: Restrict requests to GET if possible, 
         and disallow redirects to internal networks.

      **Example**:
      Instead of:
        axios.get(req.query.url);
      Do:
        // Validate or parse the provided URL, ensure it's whitelisted
        if (isAllowedDomain(req.query.url)) {
          axios.get(req.query.url);
        }
    `,
    references: [
      {
        title: 'CWE-918: Server-Side Request Forgery',
        url: 'https://cwe.mitre.org/data/definitions/918.html',
        description: 'Details on SSRF vulnerabilities and best practices'
      },
      {
        title: 'OWASP SSRF Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
        description: 'Guidelines to mitigate SSRF attacks'
      }
    ],
    cwe: '918'
  },

  sessionFixation: {
    recommendation: `
      **Why it Matters**: Session fixation allows attackers to set a session ID 
      for the victim, hijacking the session after authentication.

      **What to Do**:
      1. **Regenerate Session**: Upon login, create a new session ID.
      2. **Avoid Session IDs in URLs**: Use secure cookies and do not accept session IDs 
         from query parameters.

      **Example**:
      Instead of:
        req.session.id = req.query.sessionId;
      Do:
        // In your login flow:
        req.session.regenerate(() => {
          // safe new session
        });
    `,
    references: [
      {
        title: 'CWE-384: Session Fixation',
        url: 'https://cwe.mitre.org/data/definitions/384.html',
        description: 'Understanding session fixation vulnerabilities'
      }
    ],
    cwe: '384'
  }
};
