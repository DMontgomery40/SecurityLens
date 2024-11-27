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
            }
        };
    }

    async parseFile(content) {
        const dependencies = {};
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (trimmedLine && !trimmedLine.startsWith('#')) {
                const [name, ...versionParts] = trimmedLine.split(/[=><~]/);
                dependencies[name.trim()] = versionParts.join('') || 'latest';
            }
        }

        return { dependencies };
    }

    async checkVulnerabilities(dependencies) {
        const findings = [];
        
        for (const [name, version] of Object.entries(dependencies)) {
            if (this.vulnerabilityPatterns.noVersionSpecified.pattern.test(name)) {
                findings.push({
                    type: 'noVersionSpecified',
                    severity: this.vulnerabilityPatterns.noVersionSpecified.severity,
                    description: this.vulnerabilityPatterns.noVersionSpecified.description,
                    package: name
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

export const pipScanner = new PipScanner();