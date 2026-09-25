import { patterns } from './patterns/index.js';
import { getErrorMetadata, normalizeError } from './errors.js';
import { createLogger, withLogContext } from './logger.js';

// Constants for ignoring third-party content
const IGNORED_DOMAINS = [
  // Analytics & Tracking
  /google-?analytics?\.com/i,
  /google-?tag-?manager\.com/i,
  /google-?optimize\.com/i,
  /gtag\/js/i,
  /googletagmanager\.com/i,
  /analytics?\./i,
  /doubleclick\.net/i,
  
  // Framer
  /framer\.com/i,
  /events\.framer\.com/i,
  
  // HubSpot
  /hubspot\.com/i,
  /hs-?scripts?\.com/i,
  /hs-?analytics\.net/i,
  /hsadspixel\.net/i,
  /hscollectedforms\.net/i,
  /hs-?banner\.com/i,
  /hubspot-web-interactives/i,
  
  // Other Common Third-Party Services
  /segment\.com/i,
  /segment\.io/i,
  /mixpanel\.com/i,
  /hotjar\.com/i,
  /clarity\.ms/i,
  /facebook\.net/i,
  /fb\.com/i,
  /twitter\.com/i,
  /linkedin\.com/i,
  /snap\.com/i,
  /pinterest\.com/i,
];

const IGNORED_SCRIPT_CONTENT = [
  // HubSpot Script Patterns
  /HubSpot Script Loader/i,
  /hs-script/i,
  /_hsp\s*=\s*window\._hsp/i,
  /hsq_\d+/i,
  /data-hsjs-portal/i,
  /data-hs-ignore/i,
  
  // Google Analytics/Tag Manager
  /GoogleAnalyticsObject/i,
  /gtag\s*\(/i,
  /ga\s*\(\s*['"]create/i,
  
  // Generic Analytics/Tracking
  /tracking-?pixel/i,
  /pixel-?tracking/i,
  /tag-?manager/i,
  /analytics-?loader/i,
  /analytics-?script/i,
  
  // Common Third-Party Script Patterns
  /'UA-\d{4,10}-\d{1,4}'/i,  // Google Analytics ID pattern
  /'G-[A-Z0-9]{10,}'/i,      // GA4 ID pattern
  /data-pixel-id/i,
  /clearbit/i,
  /intercom/i,
  /optimizely/i,
];

export class FileScanner {
  constructor(config = {}) {
    this.config = {
      maxFileSize: 1024 * 1024, // 1MB
      patternTimeout: 30000, // 30 seconds per file
      ...config
    };
    this.logger = withLogContext(config.logger || createLogger(), {
      component: 'FileScanner'
    });

    this.logger.debug({
      patternsLoaded: !!patterns,
      patternCount: patterns ? Object.keys(patterns).length : 0,
      patternTypes: patterns ? Object.keys(patterns) : []
    }, 'Initializing vulnerability patterns');

    this.vulnerabilityPatterns = { ...patterns };

    // Validate patterns
    let validPatterns = 0;
    Object.entries(this.vulnerabilityPatterns).forEach(([key, pattern]) => {
      if (!pattern.pattern || !pattern.severity || !pattern.description) {
        this.logger.warn(
          {
            patternKey: key,
            pattern
          },
          'Ignoring invalid vulnerability pattern'
        );
        delete this.vulnerabilityPatterns[key];
      } else {
        validPatterns++;
      }
    });
    this.logger.info(
      {
        validPatterns
      },
      'File scanner initialized'
    );
  }

  /**
   * Check if a script should be ignored (third-party content)
   */
  shouldIgnoreScript(content, path) {
    // First check the path/URL against ignored domains
    if (IGNORED_DOMAINS.some(pattern => pattern.test(path))) {
      this.logger.debug(
        {
          filePath: path
        },
        'Skipping third-party script by domain'
      );
      return true;
    }

    // Then check content against known third-party script patterns
    if (IGNORED_SCRIPT_CONTENT.some(pattern => pattern.test(content))) {
      this.logger.debug(
        {
          filePath: path
        },
        'Skipping third-party script by content signature'
      );
      return true;
    }

    return false;
  }

  /**
   * Scan a single file's content for vulnerabilities
   * @param {string} fileContent - Content of the file
   * @param {string} filePath - Path of the file
   * @param {object} options - Scan options
   */
  async scanFile(fileContent, filePath, options = {}) {
    // Early return if it's a third-party script
    if (this.shouldIgnoreScript(fileContent, filePath)) {
      this.logger.debug(
        {
          filePath
        },
        'Skipping ignored script'
      );
      return [];
    }

    if (!fileContent || typeof fileContent !== 'string') {
      this.logger.warn(
        {
          filePath,
          contentType: typeof fileContent
        },
        'Skipping file with invalid content'
      );
      return [];
    }

    this.logger.debug(
      {
        filePath,
        contentLength: fileContent.length,
        activePatterns: Object.keys(this.vulnerabilityPatterns).length,
        scanType: options.scanType || 'default'
      },
      'Scanning file'
    );

    // Check file size
    const contentSize = new Blob([fileContent]).size;
    if (contentSize > this.config.maxFileSize) {
      this.logger.warn(
        {
          filePath,
          contentSize,
          maxFileSize: this.config.maxFileSize
        },
        'Skipping oversized file'
      );
      return [];
    }

    const findings = [];

    if (!this.vulnerabilityPatterns || Object.keys(this.vulnerabilityPatterns).length === 0) {
      this.logger.error('No vulnerability patterns loaded');
      return findings;
    }

    try {
      const lines = fileContent.split('\n');
      const lineOffsets = new Array(lines.length + 1).fill(0);
      for (let i = 0; i < lines.length; i++) {
        lineOffsets[i + 1] = lineOffsets[i] + lines[i].length + 1; // +1 for newline
      }
      lineOffsets[lines.length] = lineOffsets[lines.length - 1] + 1;

      for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
        try {
          const regex = new RegExp(vulnInfo.pattern, 'g');
          const matches = new Set();
          const matchInfo = new Map(); // Store match information for each line

          let match;
          while ((match = regex.exec(fileContent)) !== null) {
            let lineNumber = 0;
            while (lineNumber < lineOffsets.length && lineOffsets[lineNumber] <= match.index) {
              lineNumber++;
            }
            lineNumber--;
            matches.add(lineNumber);
            
            // Store the match information for this line
            matchInfo.set(lineNumber, {
              matchText: match[0],
              matchIndex: match.index,
              length: match[0].length
            });
          }

          if (matches.size > 0) {
            this.logger.debug(
              {
                filePath,
                vulnType,
                severity: vulnInfo.severity,
                matches: matches.size
              },
              'Pattern matched'
            );
            findings.push({
              type: vulnType,
              severity: vulnInfo.severity,
              description: vulnInfo.description,
              file: filePath,
              lineNumbers: Array.from(matches).sort((a, b) => a - b),
              category: vulnInfo.category,
              subcategory: vulnInfo.subcategory,
              cwe: vulnInfo.cwe,
              matchInfo: matchInfo // Add match information to finding
            });
          }
        } catch (error) {
          this.logger.warn(
            {
              ...getErrorMetadata(
                normalizeError(error, {
                  code: 'PATTERN_SCAN_FAILED',
                  status: 500,
                  message: `Error processing pattern ${vulnType}`,
                  details: {
                    filePath,
                    vulnType
                  },
                  expose: false
                })
              )
            },
            'Pattern scan failed'
          );
        }
      }

      // Add scan type to findings and generate code lines for all scan types
      findings.forEach(finding => {
        finding.scanType = options.scanType || 'local';
        
        // Generate codeLines for ALL scan types, showing the actual matched snippet
        finding.codeLines = finding.lineNumbers.map(lineNum => {
          const code = lines[lineNum - 1] || '';
          const matchDetails = finding.matchInfo.get(lineNum);
          
          // For web scans with minified code, show context around match
          if (options.scanType === 'web' && code.length > 500 && matchDetails) {
            const contextSize = 50; // Characters of context to show
            const start = Math.max(0, matchDetails.matchIndex - contextSize);
            const end = Math.min(code.length, matchDetails.matchIndex + matchDetails.length + contextSize);
            
            // Extract the relevant portion and highlight the match
            const before = code.substring(start, matchDetails.matchIndex);
            const matched = code.substring(matchDetails.matchIndex, matchDetails.matchIndex + matchDetails.length);
            const after = code.substring(matchDetails.matchIndex + matchDetails.length, end);
            
            return {
              line: lineNum,
              code: `...${before}<mark class="bg-yellow-500/20 text-white px-1 rounded">${matched}</mark>${after}...`,
              isMinified: true,
              isHtml: true
            };
          }
          
          // For all other cases, show the line with the matched text highlighted
          if (matchDetails) {
            const fullLine = code.trim();
            const matchedText = matchDetails.matchText;
            
            // Highlight the matched portion within the line
            const highlightedLine = fullLine.replace(
              new RegExp(matchedText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'),
              `**${matchedText}**`
            );
            
            return {
              line: lineNum,
              code: highlightedLine,
              matchedText: matchedText, // Include the specific matched text
              isMinified: false,
              isHtml: false
            };
          }
          
          // Fallback - show the full line
          return {
            line: lineNum,
            code: code.trim() || '',
            isMinified: false,
            isHtml: false
          };
        });
      });

      this.logger.debug(
        {
          filePath,
          findings: findings.length
        },
        'File scan completed'
      );

      return findings;
    } catch (error) {
      const normalized = normalizeError(error, {
        code: 'FILE_SCAN_FAILED',
        status: 500,
        message: `Failed to scan file ${filePath}`,
        details: {
          filePath,
          patternsLoaded: !!this.vulnerabilityPatterns,
          patternCount: this.vulnerabilityPatterns ? Object.keys(this.vulnerabilityPatterns).length : 0,
          fileSize: fileContent ? fileContent.length : 0
        },
        expose: false
      });

      this.logger.error(getErrorMetadata(normalized), 'File scan failed');
      throw normalized;
    }
  }

  /**
   * Scan multiple files
   * @param {Array} files - Array of {path, content} objects
   * @param {object} options - Scan options
   * @param {function} onProgress - Progress callback
   */
  async scanFiles(files, options = {}, onProgress = null) {
    const findings = [];
    const totalFiles = files.length;
    let processedFiles = 0;

    if (onProgress) {
      onProgress({ phase: 'analyzing', current: 0, total: totalFiles });
    }

    for (const file of files) {
      try {
        if (onProgress) {
          onProgress({ 
            phase: 'analyzing', 
            current: processedFiles, 
            total: totalFiles, 
            details: { currentFile: file.path } 
          });
        }
        
        const fileFindings = await this.scanFile(file.content, file.path, options);
        findings.push(...fileFindings);
      } catch (error) {
        this.logger.warn(
          {
            ...getErrorMetadata(
              normalizeError(error, {
                code: 'BATCH_FILE_SCAN_FAILED',
                status: 500,
                message: `Failed to scan ${file.path}`,
                details: {
                  filePath: file.path
                },
                expose: false
              })
            )
          },
          'Continuing after file scan failure'
        );
      } finally {
        processedFiles++;
      }
    }

    if (onProgress) {
      onProgress({ phase: 'analyzing', current: totalFiles, total: totalFiles });
    }

    return findings;
  }
}

// Export constants for use in other modules
export { IGNORED_DOMAINS, IGNORED_SCRIPT_CONTENT };
