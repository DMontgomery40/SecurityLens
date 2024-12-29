import React, { useState } from 'react';

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

  // New Categories
  SSRF: '918',                 // Server-Side Request Forgery
  SESSION_MANAGEMENT: '384'    // Session management issues
};

// Core + Enhanced Patterns (so we have their “pattern” or subcategory if needed)
export const corePatterns = {
  evalExecution: {
    pattern: /eval\s*\([^)]*\)|new\s+Function\s*\(/,
    description: 'Dangerous code execution via eval() or Function constructor',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '95'
  },
  commandInjection: {
    pattern: /child_process\.exec\s*\(|\.exec\s*\(|\.spawn\s*\(/,
    description: 'Potential command injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '77'
  },
  missingAuth: {
    pattern: /authentication:\s*false|auth:\s*false|noAuth:\s*true|skipAuth/i,
    description: 'Authentication bypass or missing authentication',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '306'
  },
  hardcodedCreds: {
    pattern: /(password|secret|key|token|credential)s?\s*[:=]\s*['"`][^'"`]+['"`]/i,
    description: 'Hardcoded credentials detected',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '798'
  },
  sqlInjection: {
    pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
    description: 'Potential SQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89'
  },
  xssVulnerability: {
    pattern: /innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|\$\(.*\)\.html\s*\(/,
    description: 'Cross-site scripting vulnerability',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79'
  },
  bufferIssue: {
    pattern: /Buffer\.allocUnsafe\s*\(|new\s+Buffer\s*\(/,
    description: 'Unsafe buffer allocation',
    severity: 'HIGH',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '119'
  },
  memoryLeak: {
    pattern: /(setInterval|setTimeout)\s*\([^,]+,[^)]+\)/,
    description: 'Potential memory leak in timer/interval',
    severity: 'MEDIUM',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '401'
  },
  sensitiveData: {
    pattern: /(password|token|secret|key|credential)s?\s*=\s*[^;]+/i,
    description: 'Sensitive data exposure',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '200'
  },
  insecureTransmission: {
    pattern: /https?:\/\/(?!localhost|127\.0\.0\.1)/,
    description: 'Potential insecure data transmission',
    severity: 'MEDIUM',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '319'
  }
};

export const enhancedPatterns = {
  deserializationVuln: {
    pattern: /JSON\.parse\s*\((?![^)]*JSON\.stringify)|unserialize\s*\(/,
    description: 'Unsafe deserialization of user input',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '502'
  },
  insecureDirectObjectRef: {
    pattern: /\b(?:user|account|file|document)Id\s*=\s*(?:params|query|body|req)\.[a-zA-Z_][a-zA-Z0-9_]*/,
    description: 'Potential Insecure Direct Object Reference (IDOR)',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '639'
  },
  noSqlInjection: {
    pattern: /\$where\s*:\s*['"`]|\.find\s*\(\s*{[^}]*\$regex/,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '943'
  },
  weakCrypto: {
    pattern: /crypto\.createHash\s*\(\s*['"`]md5['"`]\)|crypto\.createHash\s*\(\s*['"`]sha1['"`]\)/,
    description: 'Use of weak cryptographic hash function',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_ISSUES,
    subcategory: '326'
  },
  sensitiveErrorInfo: {
    pattern: /catch\s*\([^)]*\)\s*{\s*(?:console\.(?:log|error)|res\.(?:json|send))\s*\([^)]*(?:err|error)/,
    description: 'Potential sensitive information in error messages',
    severity: 'MEDIUM',
    category: patternCategories.ERROR_HANDLING,
    subcategory: '209'
  },
  pathTraversal: {
    pattern: /(?:\.\.\/|\.\.\\|\.\.[/\\])[^/\\]*/,
    description: 'Potential path traversal vulnerability',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '23'
  },
  openRedirect: {
    pattern: /(?:res\.redirect|window\.location|location\.href)\s*=\s*(?:req\.(?:query|params|body)|['"`]\s*\+)/,
    description: 'Potential open redirect vulnerability',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '601'
  },
  weakPasswordHash: {
    pattern: /\.hash\s*\(\s*['"`](?:md5|sha1)['"`]\)|bcrypt\.hash\s*\([^,]*,\s*(?:[1-9]|10)\s*\)/,
    description: 'Weak password hashing detected',
    severity: 'HIGH',
    category: patternCategories.AUTHENTICATION,
    subcategory: '916'
  },
  ssrfVulnerability: {
    pattern: /((axios|fetch|request)\s*\().*(req\.query|req\.params|req\.body)/,
    description: 'Potential SSRF vulnerability from user-supplied input in request calls',
    severity: 'CRITICAL',
    category: patternCategories.SSRF,
    subcategory: '918'
  },
  sessionFixation: {
    pattern: /req\.session\.id\s*=\s*req\.(query|params|body)|session\.id\s*=\s*req\.(query|params|body)/,
    description: 'Potential session fixation vulnerability allowing attacker to set session id',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '384'
  }
};

// Recommendations
export const recommendations = {
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
        url: 'https://cwe.mitre.org/data/definitions/77.html'
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
        const safeData = JSON.parse(userInput);
    `,
    references: [
      {
        title: 'CWE-502: Deserialization of Untrusted Data',
        url: 'https://cwe.mitre.org/data/definitions/502.html'
      }
    ],
    cwe: '502'
  },
  insecureDirectObjectRef: {
    recommendation: `
      **Why it Matters**: Attackers can manipulate object IDs to 
      gain unauthorized access to sensitive resources.

      **What to Do**:
      1. **Enforce Access Checks** on the server side.
      2. **Use Opaque References** to avoid exposing direct IDs.

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
        url: 'https://cwe.mitre.org/data/definitions/639.html'
      }
    ],
    cwe: '639'
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
        db.users.find({ $where: "this.password === '" + userInput + "'" });
      Do:
        db.users.find({ password: userSuppliedPassword });
    `,
    references: [
      {
        title: 'CWE-943: Improper Neutralization of Special Elements in Data Query Logic',
        url: 'https://cwe.mitre.org/data/definitions/943.html'
      }
    ],
    cwe: '943'
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
        db.query("SELECT * FROM users WHERE id = " + userId);
      Do:
        db.query("SELECT * FROM users WHERE id = ?", [userId]);
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
        element.innerHTML = userInput;
      Do:
        element.textContent = userInput;
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
  weakCrypto: {
    recommendation: `
      **Why it Matters**: MD5 and SHA-1 are cryptographically weak.

      **What to Do**:
      1. **Use stronger hashes** like SHA-256 or better.
      2. **Implement key management** and rotate keys often.

      **Example**:
      Instead of:
        crypto.createHash('md5').update(data).digest('hex');
      Do:
        crypto.createHash('sha256').update(data).digest('hex');
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
        res.send({ stack: err.stack });
      Do:
        console.error(err);
        res.status(500).send({ error: "Something went wrong" });
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
      1. **Use path.resolve()** or similar to normalize paths.
      2. **Block ".." sequences** in user-supplied filenames.

      **Example**:
      Instead of:
        fs.readFileSync("../" + userInput);
      Do:
        const safePath = path.resolve("/safe/base", userInput);
        fs.readFileSync(safePath);
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
        res.redirect(req.query.url);
      Do:
        if (allowedUrls.includes(req.query.url)) res.redirect(req.query.url);
        else res.redirect("/error");
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
      1. **Use Strong Hashing** like bcrypt≥12, scrypt, or Argon2.
      2. **Use Salts/Pepper**.

      **Example**:
      Instead of:
        bcrypt.hash(password, 10);
      Do:
        bcrypt.hash(password, 12);
    `,
    references: [
      {
        title: 'CWE-916: Use of Password Hash With Insufficient Computational Effort',
        url: 'https://cwe.mitre.org/data/definitions/916.html'
      }
    ],
    cwe: '916'
  },
  missingAuth: {
    recommendation: `
      **Why it Matters**: Skipping authentication leaves data wide open.

      **What to Do**:
      1. **Require Auth** on all sensitive endpoints.
      2. **Use a robust auth system** or library.

      **Example**:
      Instead of:
        app.get("/admin", (req, res) => { ... });
      Do:
        app.get("/admin", requireAuth, (req, res) => { ... });
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
      # Instead of:
      const password = "supersecret123";

      # Do:
      const password = process.env.DB_PASSWORD;
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
  bufferIssue: {
    recommendation: `
      **Why it Matters**: Using Buffer.allocUnsafe or new Buffer() can expose uninitialized memory.

      **What to Do**:
      1. **Use Buffer.alloc** instead of allocUnsafe().
      2. **Zero out** buffers.

      **Example**:
      Instead of:
        let buff = new Buffer(size);
      Do:
        let buff = Buffer.alloc(size);
    `,
    references: [
      {
        title: 'CWE-119: Buffer Overflow',
        url: 'https://cwe.mitre.org/data/definitions/119.html'
      },
      {
        title: 'Node.js Buffer API Security',
        url: 'https://nodejs.org/api/buffer.html#buffer_buffer_alloc_size_fill_encoding'
      }
    ],
    cwe: '119'
  },
  memoryLeak: {
    recommendation: `
      **Why it Matters**: Memory leaks degrade performance over time.

      **What to Do**:
      1. **Track and clear** intervals/timeouts when no longer needed.
      2. **Clean up** event listeners on unmount.

      **Example**:
      Instead of:
        setInterval(doSomething, 1000);
      Do:
        const id = setInterval(doSomething, 1000);
        // later
        clearInterval(id);
    `,
    references: [
      {
        title: 'CWE-401: Memory Leak',
        url: 'https://cwe.mitre.org/data/definitions/401.html'
      }
    ],
    cwe: '401'
  },
  sensitiveData: {
    recommendation: `
      **Why it Matters**: Exposing or logging passwords, tokens, or other secrets 
      can lead to account compromise.

      **What to Do**:
      1. **Mask** or omit sensitive data in logs.
      2. **Encrypt at Rest**.

      **Example**:
      Instead of:
        console.log("Password:", password);
      Do:
        console.log("User password received.");
    `,
    references: [
      {
        title: 'CWE-200: Information Exposure',
        url: 'https://cwe.mitre.org/data/definitions/200.html'
      },
      {
        title: 'OWASP Sensitive Data Exposure',
        url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
      }
    ],
    cwe: '200'
  },
  insecureTransmission: {
    recommendation: `
      **Why it Matters**: HTTP traffic can be intercepted or modified in transit.

      **What to Do**:
      1. **Use HTTPS/TLS** everywhere.
      2. **Enforce HSTS** to prevent downgrade attacks.

      **Example**:
      Instead of:
        fetch('http://example.com');
      Do:
        fetch('https://example.com');
    `,
    references: [
      {
        title: 'CWE-319: Cleartext Transmission',
        url: 'https://cwe.mitre.org/data/definitions/319.html'
      },
      {
        title: 'OWASP Transport Layer Protection',
        url: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet'
      }
    ],
    cwe: '319'
  },
  ssrfVulnerability: {
    recommendation: `
      **Why it Matters**: SSRF can let an attacker pivot to internal services.

      **What to Do**:
      1. **Validate Outbound URLs** against an allowlist.
      2. **Block internal IP ranges**.

      **Example**:
      Instead of:
        axios.get(req.query.url);
      Do:
        if (isSafeUrl(req.query.url)) axios.get(req.query.url);
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
        req.session.id = req.query.sessionId;
      Do:
        req.session.regenerate(() => { ... });
    `,
    references: [
      {
        title: 'CWE-384: Session Fixation',
        url: 'https://cwe.mitre.org/data/definitions/384.html'
      }
    ],
    cwe: '384'
  }
};

// Severity sort order
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  if (!results) return null;

  const { findings = {}, summary = {} } = results;

  // Group by (description+severity) just like before
  const groupedFindings = Object.entries(findings).reduce((acc, [type, data]) => {
    const description = data.description || 'No description provided';
    const severity = data.severity || 'LOW';
    const key = `${description}_${severity}`;

    if (!acc[key]) {
      acc[key] = {
        type,
        description,
        severity,
        files: [],
        allLineNumbers: {},
        ...data
      };
    } else {
      // Merge file line data if same description & severity
      Object.entries(data.allLineNumbers || {}).forEach(([file, lines]) => {
        if (!acc[key].allLineNumbers[file]) {
          acc[key].allLineNumbers[file] = lines;
        } else {
          const merged = new Set([...acc[key].allLineNumbers[file], ...lines]);
          acc[key].allLineNumbers[file] = Array.from(merged).sort((a, b) => a - b);
        }
      });
    }
    return acc;
  }, {});

  // Convert to array, gather line counts, etc.
  const vulnerabilities = Object.values(groupedFindings).map((v) => {
    const filesSorted = Object.keys(v.allLineNumbers).sort();
    return { ...v, files: filesSorted };
  });

  // Sort by severity first
  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // For "View by file" grouping
  const fileGrouped = {};
  vulnerabilities.forEach((vuln) => {
    vuln.files.forEach((f) => {
      if (!fileGrouped[f]) fileGrouped[f] = [];
      fileGrouped[f].push({
        ...vuln,
        lineNumbers: vuln.allLineNumbers[f] || []
      });
    });
  });

  // We also want to show "2 Unique Vulnerabilities, 4 Total Instances" in the summary cards
  // Let's count them properly:
  const severityStats = {
    CRITICAL: { uniqueCount: 0, instanceCount: 0 },
    HIGH: { uniqueCount: 0, instanceCount: 0 },
    MEDIUM: { uniqueCount: 0, instanceCount: 0 },
    LOW: { uniqueCount: 0, instanceCount: 0 }
  };
  vulnerabilities.forEach((vuln) => {
    const sev = vuln.severity;
    severityStats[sev].uniqueCount += 1;
    // Sum line counts for total "instances"
    let totalLines = 0;
    Object.values(vuln.allLineNumbers).forEach((linesArr) => {
      totalLines += linesArr.length;
    });
    severityStats[sev].instanceCount += totalLines;
  });

  // State for filters
  const [activeSeverity, setActiveSeverity] = useState('ALL'); // or CRITICAL/HIGH...
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('type'); // 'type' or 'file'

  // Filter logic: by severity + search
  const filterMatches = (vulnOrFileName, vuln) => {
    // Matches severity?
    if (activeSeverity !== 'ALL' && vuln.severity !== activeSeverity) return false;
    // Matches search?
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    // If a vulnerability, check description + file names
    if (vuln) {
      const desc = vuln.description.toLowerCase();
      if (desc.includes(q)) return true;
      // If any file name includes q
      for (let file of vuln.files) {
        if (file.toLowerCase().includes(q)) return true;
      }
      return false;
    } else {
      // if it's a fileName, check if fileName includes search
      return vulnOrFileName.toLowerCase().includes(q);
    }
  };

  const filteredByType = vulnerabilities.filter((v) => filterMatches(null, v));
  const filteredByFile = Object.entries(fileGrouped)
    .map(([fileName, vulns]) => {
      // filter the vulns for that file
      const fv = vulns.filter((v) => filterMatches(fileName, v));
      return { fileName, vulns: fv };
    })
    .filter((group) => group.vulns.length > 0);

  // Expandable lines: we'll do a small component
  const FileLineNumbers = ({ lines }) => {
    const [expanded, setExpanded] = useState(false);
    // Show only first 5 if more than 5
    if (lines.length <= 5) {
      return <span className="text-gray-700">{lines.join(', ')}</span>;
    }
    const visible = expanded ? lines : lines.slice(0, 5);
    return (
      <>
        <span className="text-gray-700">
          {visible.join(', ')}
        </span>
        {!expanded && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="ml-2 text-blue-600 text-xs underline"
          >
            Show {lines.length - 5} more
          </button>
        )}
      </>
    );
  };

  // Renders the big vulnerability card (similar to mockup)
  const VulnerabilityCard = ({ vuln }) => {
    // Grab the recommendation
    const rec = recommendations[vuln.type];
    // If we want a pattern display, let's find it from core or enhanced patterns
    let matchedPattern = '';
    let cwe = '';
    let catNum = vuln.category || ''; // might be in the data
    let subCat = vuln.subcategory || '';

    // If the raw pattern was from the scanning logic, it might be in "corePatterns" or "enhancedPatterns"
    // We'll see if "vuln.type" is a key there
    if (corePatterns[vuln.type]) {
      matchedPattern = corePatterns[vuln.type].pattern.toString();
      catNum = corePatterns[vuln.type].category;
      subCat = corePatterns[vuln.type].subcategory;
    } else if (enhancedPatterns[vuln.type]) {
      matchedPattern = enhancedPatterns[vuln.type].pattern.toString();
      catNum = enhancedPatterns[vuln.type].category;
      subCat = enhancedPatterns[vuln.type].subcategory;
    }
    if (rec && rec.cwe) {
      cwe = rec.cwe; // e.g. "798"
    }

    // We can style severity badge
    const severityBadge = {
      CRITICAL: 'bg-red-100 text-red-800',
      HIGH: 'bg-orange-100 text-orange-800',
      MEDIUM: 'bg-yellow-100 text-yellow-800',
      LOW: 'bg-blue-100 text-blue-800'
    }[vuln.severity] || 'bg-gray-100 text-gray-700';

    return (
      <div className="vulnerability-card border border-gray-200 rounded-lg p-4">
        <div className="vuln-header flex items-start justify-between mb-4">
          <div className="vuln-title flex flex-col gap-2">
            {/* Severity badge + Title */}
            <span className={`severity-badge text-xs font-semibold px-3 py-1 rounded-full w-fit uppercase ${severityBadge}`}>
              {vuln.severity}
            </span>
            <h3 className="text-lg font-medium m-0">{vuln.description}</h3>
            {/* CWE info row */}
            <div className="cve-info text-sm flex gap-4 items-center">
              {cwe ? (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cwe}.html`}
                  className="cve-link text-blue-600 hover:underline flex items-center gap-1"
                  target="_blank"
                  rel="noreferrer"
                >
                  CWE-{cwe}
                </a>
              ) : null}
              {catNum ? (
                <span className="cve-category text-gray-600">
                  Category: {Object.keys(patternCategories).find(k => patternCategories[k] === catNum)} ({catNum})
                </span>
              ) : null}
            </div>
          </div>
        </div>

        {/* File list */}
        <div className="files-list mb-4 text-sm text-gray-700">
          {vuln.files.length > 0 ? (
            <div>Found in {vuln.files.length} file{vuln.files.length > 1 ? 's' : ''}:</div>
          ) : (
            <div>No files recorded.</div>
          )}
          {vuln.files.map((file, idx) => (
            <details
              key={`${file}-${idx}`}
              className="file-item border border-gray-200 rounded-md mt-2"
            >
              <summary className="px-3 py-2 bg-gray-50 rounded-md cursor-pointer">
                {file}
              </summary>
              <div className="file-content p-3 bg-gray-100 rounded-b-md text-sm text-gray-800">
                Lines: <FileLineNumbers lines={vuln.allLineNumbers[file]} />
              </div>
            </details>
          ))}
        </div>

        {/* Recommendation section */}
        {rec ? (
          <div className="recommendation bg-gray-50 border border-gray-200 rounded-md p-4 text-sm">
            {/* Why it Matters / What to Do / Example ... We parse the markdown-ish text */}
            {/* We'll split the recommendation into sections if you want, or just show it raw. */}
            <div
              className="prose prose-sm text-gray-800 max-w-none recommendation-section"
              dangerouslySetInnerHTML={{
                __html: rec.recommendation
                  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  .replace(/\n/g, '<br />')
              }}
            />
            {/* References */}
            {rec.references && (
              <div className="references border-t border-gray-200 mt-3 pt-3">
                <h4 className="font-medium mb-2">References</h4>
                <ul className="list-disc pl-5">
                  {rec.references.map((r, i) => (
                    <li key={i}>
                      <a
                        href={r.url}
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noreferrer"
                      >
                        {r.title || r.url}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {/* Pattern Info (Detection Pattern) */}
            {matchedPattern ? (
              <div className="pattern-info mt-3 pt-3 border-t border-gray-200">
                <h4 className="font-medium mb-2">Detection Pattern</h4>
                <p className="mb-1 text-gray-700 text-sm">
                  This vulnerability was detected using the following pattern:
                </p>
                <pre className="bg-white p-2 text-xs text-gray-800 rounded overflow-auto">
                  {matchedPattern}
                </pre>
                {catNum || subCat ? (
                  <p className="text-xs text-gray-600 mt-2">
                    Category: {Object.keys(patternCategories).find(k => patternCategories[k] === catNum)} ({catNum})<br />
                    Subcategory: {subCat}
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : (
          <div className="bg-gray-50 border border-gray-200 rounded-md p-3 text-sm">
            No recommendation found for "{vuln.type}" type.
          </div>
        )}
      </div>
    );
  };

  // Now we handle UI
  return (
    <div className="mt-8">
      <div className="scan-results bg-white shadow rounded-lg p-6">
        {/* Summary Cards */}
        <div className="summary-grid grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {/* CRITICAL */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`
              summary-card critical p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'CRITICAL' ? 'border-red-700' : 'border-transparent'}
              bg-red-50 text-red-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">Critical</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.CRITICAL.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.CRITICAL.instanceCount} Total Instances
              </div>
            </div>
          </button>

          {/* HIGH */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
            className={`
              summary-card high p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'HIGH' ? 'border-orange-700' : 'border-transparent'}
              bg-orange-50 text-orange-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">High</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.HIGH.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.HIGH.instanceCount} Total Instances
              </div>
            </div>
          </button>

          {/* MEDIUM */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
            className={`
              summary-card medium p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'MEDIUM' ? 'border-yellow-700' : 'border-transparent'}
              bg-yellow-50 text-yellow-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">Medium</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.MEDIUM.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.MEDIUM.instanceCount} Total Instances
              </div>
            </div>
          </button>

          {/* LOW */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'LOW' ? 'ALL' : 'LOW')}
            className={`
              summary-card low p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'LOW' ? 'border-blue-700' : 'border-transparent'}
              bg-blue-50 text-blue-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">Low</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.LOW.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.LOW.instanceCount} Total Instances
              </div>
            </div>
          </button>
        </div>

        {/* Show the cache notice */}
        {usedCache && (
          <div className="mb-4 flex items-center justify-between bg-blue-50 p-4 rounded-lg">
            <span className="text-blue-700">⚡ Results loaded from cache</span>
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

        {/* Toggle buttons */}
        <div className="view-toggle flex gap-1 bg-gray-200 rounded-md p-1 w-fit mb-4">
          <button
            onClick={() => setViewMode('type')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'type' ? 'bg-white font-medium' : ''
            }`}
          >
            View by Vulnerability Type
          </button>
          <button
            onClick={() => setViewMode('file')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'file' ? 'bg-white font-medium' : ''
            }`}
          >
            View by File
          </button>
        </div>

        {/* Search bar */}
        <div className="mb-6">
          <input
            type="text"
            placeholder="Search by description or file path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Actual results */}
        {viewMode === 'type' ? (
          // By vulnerability
          filteredByType.length ? (
            <div className="space-y-4">
              {filteredByType.map((vuln, i) => (
                <VulnerabilityCard key={i} vuln={vuln} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No vulnerabilities found
            </div>
          )
        ) : (
          // By file
          filteredByFile.length ? (
            <div className="space-y-4">
              {filteredByFile.map(({ fileName, vulns }) => (
                <div key={fileName} className="file-view border border-gray-200 rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-3">{fileName}</h3>
                  <div className="vulnerability-list space-y-4">
                    {vulns.map((v, idx) => (
                      <VulnerabilityCard key={`${fileName}-${idx}`} vuln={v} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No vulnerabilities found
            </div>
          )
        )}
      </div>
    </div>
  );
};

export default ScanResults;
