// Core patterns
export const corePatterns = {
    // Memory-related vulnerabilities
    bufferOverflow: {
        pattern: /Buffer\.allocUnsafe\(|new\s+Buffer\(/,
        description: 'Potential buffer overflow vulnerability',
        severity: 'HIGH'
    },
    memoryLeak: {
        pattern: /(setInterval|setTimeout)\s*\(\s*[^,]+\s*,\s*[^)]+\)/,
        description: 'Potential memory leak in timer/interval',
        severity: 'MEDIUM'
    },

    // Filesystem vulnerabilities  
    pathTraversal: {
        pattern: /\.\.(\/|\\)|\/\/|\\\\/,
        description: 'Path traversal vulnerability detected',
        severity: 'CRITICAL'
    },
    unsafeFileOps: {
        pattern: /fs\.(read|write)FileSync/,
        description: 'Unsafe synchronous file operation',
        severity: 'MEDIUM'
    },

    // Code execution vulnerabilities
    eval: {
        pattern: /eval\(|new\s+Function\(|setTimeout\(\s*["']|setInterval\(\s*["']/,
        description: 'Dangerous code execution detected',
        severity: 'CRITICAL'
    },
    commandInjection: {
        pattern: /child_process\.exec\(|\.exec\(|\.spawn\(/,
        description: 'Potential command injection vulnerability',
        severity: 'CRITICAL'
    },

    // Data vulnerabilities
    sqlInjection: {
        pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
        description: 'Potential SQL injection vulnerability',
        severity: 'CRITICAL'
    },
    xss: {
        pattern: /innerHTML|outerHTML|document\.write|\$\(.*\)\.html\(/,
        description: 'Cross-site scripting vulnerability',
        severity: 'HIGH'
    }
};

// Enhanced patterns include all core patterns plus additional checks
export const enhancedPatterns = { ...corePatterns };

// Recommendations for each vulnerability type
export const recommendations = {
    bufferOverflow: 'Use Buffer.alloc() instead of Buffer.allocUnsafe() or new Buffer()',
    memoryLeak: 'Ensure all intervals/timeouts are properly cleared',
    pathTraversal: 'Validate and sanitize all file paths',
    unsafeFileOps: 'Use asynchronous file operations',
    eval: 'Avoid using eval() or new Function()',
    commandInjection: 'Use parameterized commands and input validation',
    sqlInjection: 'Use parameterized queries or an ORM',
    xss: 'Use proper content encoding and CSP headers',
    hardcodedSecrets: 'Move secrets to environment variables or secure storage',
    insecureCrypto: 'Use strong cryptographic algorithms and proper key management',
    dynamicRequire: 'Use static imports and proper dependency management',
    unsafeDeserialization: 'Validate and sanitize data before deserialization'
};