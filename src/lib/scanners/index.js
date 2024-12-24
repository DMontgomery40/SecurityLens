// Package file patterns
export const PACKAGE_FILE_PATTERNS = {
  'package.json': 'npm',
  'requirements.txt': 'pip',
  'Gemfile': 'ruby',
  'pom.xml': 'maven',
  'build.gradle': 'gradle',
  'composer.json': 'php',
  'go.mod': 'go',
  'cargo.toml': 'rust'
};

// Base scanner interface
export class SecurityScanner {
  name = 'base';
  description = '';
  
  async scan(filePath, content) {
    throw new Error('Not implemented');
  }

  parseVersion(version) {
    const match = version.match(/^\D*(\d+(?:\.\d+)*)/);
    return match ? match[1] : version;
  }

  isVersionVulnerable(version, minVersion) {
    const v1 = this.parseVersion(version).split('.').map(Number);
    const v2 = this.parseVersion(minVersion).split('.').map(Number);
    
    for (let i = 0; i < Math.max(v1.length, v2.length); i++) {
      const num1 = v1[i] || 0;
      const num2 = v2[i] || 0;
      if (num1 < num2) return true;
      if (num1 > num2) return false;
    }
    return false;
  }
}

// NPM Package Scanner
export class NpmScanner extends SecurityScanner {
  name = 'npm';
  description = 'Scans package.json for known vulnerable dependencies';
  
  async scan(filePath, content) {
    const findings = [];
    try {
      const pkg = JSON.parse(content);
      const dependencies = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {})
      };

      // Check for outdated and vulnerable packages
      for (const [name, version] of Object.entries(dependencies)) {
        // Example checks (in production, this would connect to a vulnerability database)
        if (this.isVersionVulnerable(version, '4.17.1') && name === 'express') {
          findings.push({
            type: 'vulnerableDependency',
            severity: 'HIGH',
            description: `Vulnerable version of ${name} detected`,
            file: filePath,
            recommendation: `Update ${name} to version 4.17.1 or higher`,
            cwe: '1035', // Using Vulnerable Dependencies
            category: 'DEPENDENCY',
            subcategory: '1035'
          });
        }
      }
    } catch (error) {
      console.error('Error scanning NPM package:', error);
    }
    return findings;
  }
}

// Python Package Scanner
export class PipScanner extends SecurityScanner {
  name = 'pip';
  description = 'Scans requirements.txt for known vulnerable dependencies';
  
  async scan(filePath, content) {
    const findings = [];
    try {
      const lines = content.split('\n');
      for (const line of lines) {
        if (line.trim() && !line.startsWith('#')) {
          const [name, version] = line.split('==');
          if (version) {
            // Example check
            if (name.trim() === 'django' && this.isVersionVulnerable(version, '3.2.0')) {
              findings.push({
                type: 'vulnerableDependency',
                severity: 'HIGH',
                description: `Vulnerable version of ${name} detected`,
                file: filePath,
                recommendation: `Update ${name} to version 3.2.0 or higher`,
                cwe: '1035',
                category: 'DEPENDENCY',
                subcategory: '1035'
              });
            }
          }
        }
      }
    } catch (error) {
      console.error('Error scanning Python requirements:', error);
    }
    return findings;
  }
}

// Scanner Registry
const registry = new Map();
registry.set('npm', new NpmScanner());
registry.set('pip', new PipScanner());

export function getScannerForFile(type) {
  return registry.get(type) || null;
}

// Registry for all scanners
export class ScannerRegistry {
  scanners = new Map();

  register(scanner) {
    this.scanners.set(scanner.name, scanner);
  }

  async runAll(content, metadata) {
    const results = [];
    for (const scanner of this.scanners.values()) {
      try {
        const scanResults = await scanner.scan(content, metadata);
        results.push({
          scanner: scanner.name,
          results: scanResults
        });
      } catch (error) {
        console.error(`Scanner ${scanner.name} failed:`, error);
      }
    }
    return results;
  }
}
