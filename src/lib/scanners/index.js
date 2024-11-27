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

// Import implemented scanners
import { npmScanner } from './implementations/npm.js';
import { pipScanner } from './implementations/pip.js';

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
    'pyproject.toml': pipScanner
};

// Factory function to get the appropriate scanner
export function getScannerForFile(filename) {
    const scanner = Object.entries(PACKAGE_FILE_PATTERNS).find(([pattern]) => {
        return filename.toLowerCase().endsWith(pattern.toLowerCase());
    });
    
    return scanner ? scanner[1] : null;
}