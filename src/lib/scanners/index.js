// Base scanner interface
export class SecurityScanner {
  name = 'base';
  description = '';
  
  async scan(content, metadata) {
    throw new Error('Not implemented');
  }
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

// Example CVE scanner
export class CVEScanner extends SecurityScanner {
  name = 'cve';
  description = 'Checks dependencies against known CVEs';
  
  async scan(content, metadata) {
    // Integration with CVE API would go here
    return [];
  }
}