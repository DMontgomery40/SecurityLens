import { BaseScanner } from '../index.js';

class PipScanner extends BaseScanner {
    constructor() {
        super();
        this.vulnerabilityPatterns = {
            insecureVersion: {
                pattern: /==\s*([0-9]+)\.([0-9]+)\.([0-9]+)/,
                severity: 'MEDIUM',
                description: 'Pinned to potentially vulnerable version'
            },
            noVersionSpecified: {
                pattern: /^([a-zA-Z0-9-_.]+)$/,
                severity: 'HIGH',
                description: 'No version specified, could pull vulnerable version'
            },
            outdatedPackage: {
                pattern: /==\s*0\./,
                severity: 'MEDIUM',
                description: 'Using potentially unstable version (0.x)'
            }
        };
    }

    async parseFile(content) {
        const dependencies = {};
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (trimmedLine && !trimmedLine.startsWith('#')) {
                // Handle various requirement formats
                let name, version;
                if (trimmedLine.includes('==')) {
                    [name, version] = trimmedLine.split('==').map(s => s.trim());
                } else if (trimmedLine.includes('>=')) {
                    [name, version] = trimmedLine.split('>=').map(s => s.trim());
                } else if (trimmedLine.includes('>')) {
                    [name, version] = trimmedLine.split('>').map(s => s.trim());
                } else if (trimmedLine.includes('~=')) {
                    [name, version] = trimmedLine.split('~=').map(s => s.trim());
                } else {
                    name = trimmedLine;
                    version = null;
                }

                if (name) {
                    dependencies[name] = version || 'unspecified';
                }
            }
        }

        return { dependencies };
    }

    async scan(filePath, content) {
        const findings = [];
        
        try {
            const parsedData = await this.parseFile(content);
            
            for (const [name, version] of Object.entries(parsedData.dependencies)) {
                // Check for missing version specifications
                if (version === 'unspecified') {
                    findings.push({
                        type: 'noVersionSpecified',
                        severity: this.vulnerabilityPatterns.noVersionSpecified.severity,
                        description: this.vulnerabilityPatterns.noVersionSpecified.description,
                        package: name,
                        file: filePath
                    });
                }
                // Check for pinned versions
                else if (version.startsWith('==')) {
                    findings.push({
                        type: 'insecureVersion',
                        severity: this.vulnerabilityPatterns.insecureVersion.severity,
                        description: this.vulnerabilityPatterns.insecureVersion.description,
                        package: name,
                        version: version,
                        file: filePath
                    });
                }
                // Check for unstable versions
                if (version && version.includes('0.')) {
                    findings.push({
                        type: 'outdatedPackage',
                        severity: this.vulnerabilityPatterns.outdatedPackage.severity,
                        description: this.vulnerabilityPatterns.outdatedPackage.description,
                        package: name,
                        version: version,
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

export const pipScanner = new PipScanner();