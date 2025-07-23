import { recommendations } from './patterns/index.js';

export class ReportBuilder {
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Generate a structured report from findings
   * @param {Array} findings - Array of vulnerability findings
   * @param {object} metadata - Additional metadata (rateLimitInfo, fromCache, etc.)
   */
  generateReport(findings, metadata = {}) {
    // Group findings by type
    const groupedFindings = findings.reduce((acc, finding) => {
      if (!acc[finding.type]) {
        acc[finding.type] = {
          severity: finding.severity,
          description: finding.description,
          category: finding.category,
          subcategory: finding.subcategory,
          files: [],
          allLineNumbers: {},
          allCodeLines: {}, // Store code lines by file
          scanType: finding.scanType,
          cwe: finding.cwe
        };
      }
      // Add file to files array if not already present
      if (finding.file && !acc[finding.type].files.includes(finding.file)) {
        acc[finding.type].files.push(finding.file);
      }
      // Aggregate line numbers by file
      if (finding.file && finding.lineNumbers) {
        acc[finding.type].allLineNumbers[finding.file] = finding.lineNumbers;
      }
      // Aggregate code lines by file
      if (finding.file && finding.codeLines) {
        acc[finding.type].allCodeLines[finding.file] = finding.codeLines;
      }
      return acc;
    }, {});

    // Convert to array format
    const processedFindings = Object.entries(groupedFindings).map(([type, data]) => ({
      type,
      severity: data.severity,
      description: data.description,
      category: data.category,
      subcategory: data.subcategory,
      files: data.files,
      allLineNumbers: data.allLineNumbers,
      allCodeLines: data.allCodeLines, // Include all code lines grouped by file
      scanType: data.scanType,
      cwe: data.cwe
    }));

    // Calculate severity stats
    const severityStats = processedFindings.reduce((acc, finding) => {
      const severity = finding.severity || 'LOW';
      const instanceCount = Object.values(finding.allLineNumbers)
        .reduce((sum, lines) => sum + lines.length, 0);

      if (!acc[severity]) {
        acc[severity] = { uniqueCount: 0, instanceCount: 0 };
      }
      acc[severity].uniqueCount++;
      acc[severity].instanceCount += instanceCount;
      return acc;
    }, {
      CRITICAL: { uniqueCount: 0, instanceCount: 0 },
      HIGH: { uniqueCount: 0, instanceCount: 0 },
      MEDIUM: { uniqueCount: 0, instanceCount: 0 },
      LOW: { uniqueCount: 0, instanceCount: 0 }
    });

    const report = {
      findings: processedFindings,
      summary: {
        totalIssues: processedFindings.length,
        criticalIssues: severityStats.CRITICAL.uniqueCount,
        highIssues: severityStats.HIGH.uniqueCount,
        mediumIssues: severityStats.MEDIUM.uniqueCount,
        lowIssues: severityStats.LOW.uniqueCount,
        criticalInstances: severityStats.CRITICAL.instanceCount,
        highInstances: severityStats.HIGH.instanceCount,
        mediumInstances: severityStats.MEDIUM.instanceCount,
        lowInstances: severityStats.LOW.instanceCount
      }
    };

    // Add metadata
    if (metadata.rateLimit) {
      report.rateLimit = metadata.rateLimit;
    }
    if (metadata.fromCache !== undefined) {
      report.fromCache = metadata.fromCache;
    }

    return report;
  }

  /**
   * Generate recommendations based on findings
   * @param {Array} findings - Array of vulnerability findings
   */
  generateRecommendations(findings) {
    const uniqueRecs = new Set();

    findings.forEach(finding => {
      const rec = recommendations[finding.type];
      if (rec) {
        uniqueRecs.add(JSON.stringify({
          type: finding.type,
          recommendation: typeof rec.recommendation === 'string' ? rec.recommendation : 'Review and fix the identified issue',
          references: rec.references || [],
          cwe: rec.cwe || finding.cwe
        }));
      }
    });

    return Array.from(uniqueRecs).map(rec => JSON.parse(rec));
  }

  /**
   * Generate summary statistics from findings
   * @param {Array} findings - Array of vulnerability findings
   */
  generateSummary(findings) {
    const summary = {
      totalIssues: 0,
      criticalIssues: 0,
      highIssues: 0,
      mediumIssues: 0,
      lowIssues: 0,
      criticalInstances: 0,
      highInstances: 0,
      mediumInstances: 0,
      lowInstances: 0,
      filesCovered: new Set(),
      vulnerabilityTypes: new Set()
    };

    findings.forEach(finding => {
      const severity = finding.severity || 'LOW';
      const instanceCount = finding.lineNumbers ? finding.lineNumbers.length : 1;
      
      summary.totalIssues++;
      summary.vulnerabilityTypes.add(finding.type);
      
      if (finding.file) {
        summary.filesCovered.add(finding.file);
      }

      switch (severity) {
        case 'CRITICAL':
          summary.criticalIssues++;
          summary.criticalInstances += instanceCount;
          break;
        case 'HIGH':
          summary.highIssues++;
          summary.highInstances += instanceCount;
          break;
        case 'MEDIUM':
          summary.mediumIssues++;
          summary.mediumInstances += instanceCount;
          break;
        case 'LOW':
          summary.lowIssues++;
          summary.lowInstances += instanceCount;
          break;
      }
    });

    // Convert sets to arrays/counts
    summary.filesCovered = summary.filesCovered.size;
    summary.vulnerabilityTypes = summary.vulnerabilityTypes.size;

    return summary;
  }

  /**
   * Format findings for console output
   * @param {Array} findings - Array of vulnerability findings
   */
  formatConsoleReport(findings) {
    if (!findings || findings.length === 0) {
      return 'No vulnerabilities found.';
    }

    const report = this.generateReport(findings);
    const summary = report.summary;
    
    let output = '\nVulnerability Scan Report\n';
    output += '========================\n\n';
    
    output += 'Summary:\n';
    output += `Critical Issues: ${summary.criticalIssues} (${summary.criticalInstances} instances)\n`;
    output += `High Issues: ${summary.highIssues} (${summary.highInstances} instances)\n`;
    output += `Medium Issues: ${summary.mediumIssues} (${summary.mediumInstances} instances)\n`;
    output += `Low Issues: ${summary.lowIssues} (${summary.lowInstances} instances)\n`;
    output += `Total Unique Issues: ${summary.totalIssues}\n\n`;
    
    output += 'Detailed Findings:\n\n';
    
    report.findings.forEach(finding => {
      output += `${finding.type} (${finding.severity})\n`;
      output += `Description: ${finding.description}\n`;
      
      if (finding.files && finding.files.length > 0) {
        finding.files.forEach(file => {
          output += `File: ${file}\n`;
          if (finding.allLineNumbers[file]) {
            output += `Lines: ${finding.allLineNumbers[file].join(', ')}\n`;
          }
        });
      } else {
        output += 'File: undefined\n';
      }
      
      output += '\n';
    });

    output += 'Recommendations:';
    return output;
  }
}