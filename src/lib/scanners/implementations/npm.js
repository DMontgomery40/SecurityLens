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

    async checkVulnerabilities(dependencies) {
        const findings = [];
        
        for (const [name, version] of Object.entries(dependencies)) {
            if (this.vulnerabilityPatterns.insecureVersionRange.pattern.test(version)) {
                findings.push({
                    type: 'insecureVersionRange',
                    severity: this.vulnerabilityPatterns.insecureVersionRange.severity,
                    description: this.vulnerabilityPatterns.insecureVersionRange.description,
                    package: name,
                    version: version
                });
            }
        }

        return findings;
    }

    async scan(filePath, content) {
        const parsedData = await this.parseFile(content);
        return this.checkVulnerabilities(parsedData.dependencies);
    }
}

export const npmScanner = new NPMScanner();