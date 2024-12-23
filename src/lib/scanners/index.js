// Basic scanner interface
export class BaseScanner {
    async scan(filePath, content) {
        // Default implementation returns no findings
        return [];
    }
}

// Map of file patterns to their types
export const PACKAGE_FILE_PATTERNS = {
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'yarn',
    'requirements.txt': 'pip',
    'setup.py': 'pip',
    'Pipfile': 'pip',
    'pyproject.toml': 'poetry'
};

class NpmScanner extends BaseScanner {
    async scan(filePath, content) {
        const findings = [];
        try {
            const pkg = JSON.parse(content);
            
            // Check dependencies for known vulnerable patterns
            const depsToCheck = {
                ...pkg.dependencies,
                ...pkg.devDependencies
            };

            for (const [dep, version] of Object.entries(depsToCheck)) {
                if (version.includes('*') || version === 'latest') {
                    findings.push({
                        type: 'unsafeVersionPattern',
                        severity: 'HIGH',
                        description: `Unsafe version pattern found for ${dep}: ${version}`,
                        file: filePath,
                        package: dep,
                        version: version,
                        recommendation: 'Specify exact versions for dependencies to prevent automatic updates to potentially vulnerable versions'
                    });
                }
            }
        } catch (error) {
            console.error(`Error scanning ${filePath}:`, error);
        }
        return findings;
    }
}

export function getScannerForFile(type) {
    switch (type) {
        case 'npm':
            return new NpmScanner();
        default:
            return new BaseScanner();
    }
}