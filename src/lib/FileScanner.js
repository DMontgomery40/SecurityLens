import { patterns } from './patterns/index.js';

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

    // Enhanced debug logging
    console.log('Initializing scanner with patterns:', {
      patternsLoaded: !!patterns,
      patternCount: patterns ? Object.keys(patterns).length : 0,
      patternTypes: patterns ? Object.keys(patterns) : []
    });

    this.vulnerabilityPatterns = { ...patterns };

    // Validate patterns
    let validPatterns = 0;
    Object.entries(this.vulnerabilityPatterns).forEach(([key, pattern]) => {
      if (!pattern.pattern || !pattern.severity || !pattern.description) {
        console.error(`Invalid pattern configuration for ${key}:`, pattern);
        delete this.vulnerabilityPatterns[key];
      } else {
        validPatterns++;
      }
    });
    console.log(`Scanner initialized with ${validPatterns} valid patterns`);
  }

  /**
   * Check if a script should be ignored (third-party content)
   */
  shouldIgnoreScript(content, path) {
    // First check the path/URL against ignored domains
    if (IGNORED_DOMAINS.some(pattern => pattern.test(path))) {
      console.debug('Ignoring script from third-party domain:', path);
      return true;
    }

    // Then check content against known third-party script patterns
    if (IGNORED_SCRIPT_CONTENT.some(pattern => pattern.test(content))) {
      console.debug('Ignoring third-party script content:', path);
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
      console.debug('Skipping third-party script:', filePath);
      return [];
    }

    console.log(`Scanning file: ${filePath}`, {
      contentProvided: !!fileContent,
      contentLength: fileContent ? fileContent.length : 0,
      activePatterns: Object.keys(this.vulnerabilityPatterns).length
    });

    if (!fileContent || typeof fileContent !== 'string') {
      console.error('Invalid file content provided to scanner');
      return [];
    }

    // Check file size
    const contentSize = new Blob([fileContent]).size;
    if (contentSize > this.config.maxFileSize) {
      console.warn(`File ${filePath} exceeds size limit of ${this.config.maxFileSize} bytes`);
      return [];
    }

    const findings = [];

    if (!this.vulnerabilityPatterns || Object.keys(this.vulnerabilityPatterns).length === 0) {
      console.error('No vulnerability patterns loaded');
      return findings;
    }

    try {
      const lines = fileContent.split('\n');
      const lineOffsets = new Array(lines.length + 1).fill(0);
      for (let i = 0; i < lines.length; i++) {
        lineOffsets[i + 1] = lineOffsets[i] + lines[i].length + 1; // +1 for newline
      }
      lineOffsets[lines.length] = lineOffsets[lines.length - 1] + 1;

      // Log file type and first few lines for debugging
      const fileExt = filePath.split('.').pop().toLowerCase();
      console.log(`File type: ${fileExt}, First few lines:`, lines.slice(0, 3));

      for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
        try {
          console.log(`Checking pattern: ${vulnType}`, {
            pattern: vulnInfo.pattern,
            severity: vulnInfo.severity
          });

          const regex = new RegExp(vulnInfo.pattern, 'g');
          const matches = new Set();
          const matchInfo = new Map(); // Store match information for each line

          let match;
          while ((match = regex.exec(fileContent)) !== null) {
            console.log(`Found match for ${vulnType}:`, {
              matchText: match[0],
              matchIndex: match.index
            });

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
            console.log(`Found ${matches.size} matches for ${vulnType} in ${filePath}`);
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
          console.error(`Error processing pattern ${vulnType}:`, error);
        }
      }

      console.log('Generated findings with categories:', findings.map(f => ({
        type: f.type, 
        category: f.category,
        subcategory: f.subcategory,
        lineCount: f.lineNumbers.length
      })));

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

      return findings;
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
      console.error('Scan context:', {
        patternsLoaded: !!this.vulnerabilityPatterns,
        patternCount: this.vulnerabilityPatterns ? Object.keys(this.vulnerabilityPatterns).length : 0,
        fileSize: fileContent ? fileContent.length : 0
      });
      throw error;
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
        console.error(`Error scanning file ${file.path}:`, error);
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