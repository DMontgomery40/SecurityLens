import { BaseScanner } from '../index.js';

class NPMScanner extends BaseScanner {
    constructor() {
        super();
        this.vulnerabilityPatterns = {
            insecureVersionRange: {
                pattern: /^\s*[~^]\d+/,
                severity: 'MEDIUM',
                description: 'Using ^ or ~ in version ranges can lead to auto-updating to vulnerable versions'
            },
            outdatedPackageVersion: {
                pattern: /"version"\s*:\s*"([0-9]+)\.([0-9]+)\.([0-9]+)"/,
                severity: 'LOW',
                description: 'Package version may be outdated'
            },
            noLockFile: {
                pattern: /package\.json$/,
                severity: 'MEDIUM',
                description: 'No package lock file found'
            }
        };
    }

    async parseFile(content) {
        try {
            const packageData = JSON.parse(content);
            return {
                dependencies: { 
                    ...packageData.dependencies,
                    ...packageData.devDependencies
                },
                metadata: {
                    name: packageData.name,
                    version: packageData.version
                }
            };
        } catch (error) {
            throw new Error(`Failed to parse package.json: ${error.message}`);
        }
    }

    async scan(filePath, content) {
        const findings = [];
        
        try {
            const parsedData = await this.parseFile(content);
            
            // Check dependencies
            for (const [name, version] of Object.entries(parsedData.dependencies || {})) {
                if (this.vulnerabilityPatterns.insecureVersionRange.pattern.test(version)) {
                    findings.push({
                        type: 'insecureVersionRange',
                        severity: this.vulnerabilityPatterns.insecureVersionRange.severity,
                        description: this.vulnerabilityPatterns.insecureVersionRange.description,
                        package: name,
                        version: version,
                        file: filePath
                    });
                }
            }

            // Check package version
            if (parsedData.metadata?.version) {
                const versionParts = parsedData.metadata.version.split('.');
                const majorVersion = parseInt(versionParts[0]);
                if (majorVersion === 0 || isNaN(majorVersion)) {
                    findings.push({
                        type: 'unstableVersion',
                        severity: 'MEDIUM',
                        description: 'Using unstable version (0.x.x)',
                        package: parsedData.metadata.name,
                        version: parsedData.metadata.version,
                        file: filePath
                    });
                }
            }

        } catch (error) {
            console.error(`Error scanning ${filePath}:`, error.message);
        }

        return findings;
    }
}

export const npmScanner = new NPMScanner();