import { npmScanner } from './npm';
import { pipScanner } from './pip';
import { gemScanner } from './gem';
import { mavenScanner } from './maven';
import { composerScanner } from './composer';
import { goModScanner } from './gomod';
import { cargoScanner } from './cargo';

// Map of file patterns to their respective scanners
export const PACKAGE_FILE_PATTERNS = {
  // Node.js
  'package.json': npmScanner,
  'package-lock.json': npmScanner,
  'yarn.lock': npmScanner,
  
  // Python
  'requirements.txt': pipScanner,
  'setup.py': pipScanner,
  'Pipfile': pipScanner,
  'pyproject.toml': pipScanner,
  
  // Ruby
  'Gemfile': gemScanner,
  'Gemfile.lock': gemScanner,
  
  // Java
  'pom.xml': mavenScanner,
  'build.gradle': mavenScanner,
  
  // PHP
  'composer.json': composerScanner,
  'composer.lock': composerScanner,
  
  // Go
  'go.mod': goModScanner,
  'go.sum': goModScanner,
  
  // Rust
  'Cargo.toml': cargoScanner,
  'Cargo.lock': cargoScanner,
};

// Base scanner interface that all scanners should implement
export class BaseScanner {
  async scan(filePath, content) {
    throw new Error('Scan method must be implemented');
  }

  async parseFile(content) {
    throw new Error('ParseFile method must be implemented');
  }

  async checkVulnerabilities(dependencies) {
    throw new Error('CheckVulnerabilities method must be implemented');
  }
}

// Factory function to get the appropriate scanner
export function getScannerForFile(filename) {
  const scanner = Object.entries(PACKAGE_FILE_PATTERNS).find(([pattern]) => {
    return filename.toLowerCase().endsWith(pattern.toLowerCase());
  });
  
  return scanner ? scanner[1] : null;
}
