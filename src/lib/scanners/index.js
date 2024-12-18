// Basic scanner interface
export class BaseScanner {
    async scan(filePath, content) {
        // Default implementation returns no findings
        return [];
    }
}

// Map of file patterns to their types
export const PACKAGE_FILE_PATTERNS = {
    // Node.js
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'npm',
    
    // Python
    'requirements.txt': 'pip',
    'setup.py': 'pip',
    'Pipfile': 'pip',
    'pyproject.toml': 'pip'
};

// Get appropriate scanner
export function getScannerForFile(filename) {
    const pattern = Object.entries(PACKAGE_FILE_PATTERNS).find(([pattern]) => 
        filename.toLowerCase().endsWith(pattern.toLowerCase())
    );
    
    return pattern ? new BaseScanner() : null;
}