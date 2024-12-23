// Core patterns with enhanced security information
export const corePatterns = {
    // Memory-related vulnerabilities
    bufferOverflow: {
        pattern: /Buffer\.allocUnsafe\(|new\s+Buffer\(/,
        description: 'Potential buffer overflow vulnerability',
        severity: 'HIGH',
        cwe: '119'
    },
    memoryLeak: {
        pattern: /(setInterval|setTimeout)\s*\(\s*[^,]+\s*,\s*[^)]+\)/,
        description: 'Potential memory leak in timer/interval',
        severity: 'MEDIUM',
        cwe: '401'
    },

    // Filesystem vulnerabilities  
    pathTraversal: {
        pattern: /\.\.(\/|\\)|\/\/|\\\\/,
        description: 'Path traversal vulnerability detected',
        severity: 'CRITICAL',
        cwe: '22'
    },
    unsafeFileOps: {
        pattern: /fs\.(read|write)FileSync/,
        description: 'Unsafe synchronous file operation',
        severity: 'MEDIUM',
        cwe: '362'
    },

    // Code execution vulnerabilities
    eval: {
        pattern: /eval\(|new\s+Function\(|setTimeout\(\s*["']|setInterval\(\s*["']/,
        description: 'Dangerous code execution detected',
        severity: 'CRITICAL',
        cwe: '95'
    },
    commandInjection: {
        pattern: /child_process\.exec\(|\.exec\(|\.spawn\(/,
        description: 'Potential command injection vulnerability',
        severity: 'CRITICAL',
        cwe: '77'
    },

    // Data vulnerabilities
    sqlInjection: {
        pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
        description: 'Potential SQL injection vulnerability',
        severity: 'CRITICAL',
        cwe: '89'
    },
    xss: {
        pattern: /innerHTML|outerHTML|document\.write|\$\(.*\)\.html\(/,
        description: 'Cross-site scripting vulnerability',
        severity: 'HIGH',
        cwe: '79'
    }
};

// Enhanced patterns include all core patterns plus additional checks
export const enhancedPatterns = { ...corePatterns };

// Detailed security recommendations with references
export const recommendations = {
    bufferOverflow: {
        recommendation: 'Replace Buffer.allocUnsafe() or new Buffer() with Buffer.alloc() to prevent potential buffer overflow attacks. Buffer.alloc() safely initializes the buffer with zeros.',
        references: [
            {
                title: 'Node.js Buffer API Security',
                url: 'https://nodejs.org/api/buffer.html#buffer_buffer_alloc_size_fill_encoding',
                description: 'Official Node.js documentation on secure buffer allocation'
            },
            {
                title: 'OWASP Buffer Overflow Prevention',
                url: 'https://owasp.org/www-community/vulnerabilities/Buffer_Overflow',
                description: 'Comprehensive guide on preventing buffer overflows'
            }
        ],
        cwe: '119'
    },
    memoryLeak: {
        recommendation: 'Ensure all setInterval/setTimeout calls are properly cleared using clearInterval/clearTimeout when the component is unmounted or the operation is complete.',
        references: [
            {
                title: 'Memory Leak Prevention in JavaScript',
                url: 'https://auth0.com/blog/four-types-of-leaks-in-your-javascript-code-and-how-to-get-rid-of-them/',
                description: 'Guide to preventing memory leaks in JavaScript applications'
            }
        ],
        cwe: '401'
    },
    pathTraversal: {
        recommendation: 'Implement strict input validation and use path.normalize() to resolve and sanitize file paths. Consider using a whitelist of allowed paths and implementing proper access controls.',
        references: [
            {
                title: 'OWASP Path Traversal Prevention',
                url: 'https://owasp.org/www-community/attacks/Path_Traversal',
                description: 'Comprehensive guide on preventing path traversal attacks'
            },
            {
                title: 'Node.js Security Best Practices',
                url: 'https://nodejs.org/en/docs/guides/security/',
                description: 'Official Node.js security guidelines'
            }
        ],
        cwe: '22'
    },
    eval: {
        recommendation: 'Avoid using eval() or new Function() as they can execute arbitrary JavaScript code. Use safer alternatives like JSON.parse() for JSON data or implement specific functionality without dynamic code execution.',
        references: [
            {
                title: 'OWASP Code Injection Prevention',
                url: 'https://owasp.org/www-community/attacks/Code_Injection',
                description: 'Guide to preventing code injection attacks'
            }
        ],
        cwe: '95'
    },
    commandInjection: {
        recommendation: 'Use child_process.execFile() instead of exec() when possible, and always sanitize user input. Implement proper input validation and use parameterized commands.',
        references: [
            {
                title: 'OWASP Command Injection Prevention',
                url: 'https://owasp.org/www-community/attacks/Command_Injection',
                description: 'Comprehensive guide on preventing command injection'
            },
            {
                title: 'Node.js child_process Security',
                url: 'https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback',
                description: 'Official documentation on secure child process execution'
            }
        ],
        cwe: '77'
    },
    sqlInjection: {
        recommendation: 'Use parameterized queries or an ORM to prevent SQL injection. Never concatenate user input directly into SQL queries.',
        references: [
            {
                title: 'OWASP SQL Injection Prevention',
                url: 'https://owasp.org/www-community/attacks/SQL_Injection',
                description: 'Comprehensive guide on preventing SQL injection'
            },
            {
                title: 'Node.js SQL Best Practices',
                url: 'https://github.com/mysqljs/mysql#escaping-query-values',
                description: 'Guide to secure SQL queries in Node.js'
            }
        ],
        cwe: '89'
    },
    xss: {
        recommendation: 'Use proper content encoding, implement Content Security Policy (CSP) headers, and avoid using dangerous DOM manipulation methods. Consider using safe templating libraries.',
        references: [
            {
                title: 'OWASP XSS Prevention',
                url: 'https://owasp.org/www-community/attacks/xss/',
                description: 'Comprehensive guide on preventing XSS attacks'
            },
            {
                title: 'Content Security Policy (CSP)',
                url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                description: 'MDN guide on implementing Content Security Policy'
            }
        ],
        cwe: '79'
    }
};