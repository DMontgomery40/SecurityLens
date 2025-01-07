/**  
##!/usr/bin/env bash
# ------------------------------------------------------------------------------
#  Step A: Create a new folder for your merge script (or use existing SecurityLens dir)
# ------------------------------------------------------------------------------
# mkdir -p /tmp/SecurityLens
# cd /tmp/SecurityLens

# ------------------------------------------------------------------------------
#  Step B: Initialize a Node project (if you haven't already)
# ------------------------------------------------------------------------------
# npm init -y

# ------------------------------------------------------------------------------
#  Step C: Install dependencies we'll need
# ------------------------------------------------------------------------------
# npm install simple-git js-yaml fs-extra

# ------------------------------------------------------------------------------
#  Step D: Create the merge script file
# ------------------------------------------------------------------------------
# cat << 'EOF' > merge_semgrep_rules.js
#!/usr/bin/env node
*/
/**
 * merge_semgrep_rules.js
 *
 * Purpose:
 *  1. Clones (or pulls) the semgrep-rules repo into a local folder.
 *  2. Recursively scans all .yaml rule files.
 *  3. Merges them into your "patterns" + "recommendations" style JSON structures:
 *     - merged_semgrep_patterns.json
 *     - merged_semgrep_recommendations.json
 *
 * Usage:
 *   node merge_semgrep_rules.js
 *
 * Requirements:
 *   - Git installed (for cloning/pulling semgrep-rules).
 *   - Node.js + npm installed
 *   - "simple-git" + "js-yaml" + "fs-extra"
 *
 * Note:
 *   This is just a one-time or occasional utility to pull in fresh semgrep patterns.
 *   You’ll likely want to manually commit the generated files to your codebase,
 *   or host them for your scanner to fetch at runtime.
 */

const path = require('path');
const fs = require('fs-extra');
const yaml = require('js-yaml');
const simpleGit = require('simple-git');

// The remote repo for semgrep community rules
const SEMGREP_RULES_REPO = 'https://github.com/returntocorp/semgrep-rules.git';
// Where we clone/pull them
const SEMGREP_RULES_DIR = path.join(__dirname, 'semgrep-rules');

// Our output files
const PATTERNS_OUTPUT_FILE = path.join(__dirname, 'merged_semgrep_patterns.json');
const RECOMMENDATIONS_OUTPUT_FILE = path.join(__dirname, 'merged_semgrep_recommendations.json');

// If you want to do special mapping from semgrep severities to your severities, edit this:
const severityMap = {
  'ERROR':   'HIGH',
  'WARNING': 'MEDIUM',
  'INFO':    'LOW'
  // You can add more or handle custom severities as needed
};

// We'll store patterns + recs in these
const mergedPatterns = {};
const mergedRecommendations = {};

/**
 * Clone or pull the semgrep-rules repo.
 */
async function cloneOrPullSemgrepRules() {
  // Check if directory already exists
  if (!fs.existsSync(SEMGREP_RULES_DIR)) {
    console.log(`Cloning semgrep-rules into: ${SEMGREP_RULES_DIR}`);
    await simpleGit().clone(SEMGREP_RULES_REPO, SEMGREP_RULES_DIR);
  } else {
    console.log(`Pulling latest changes in semgrep-rules at: ${SEMGREP_RULES_DIR}`);
    const git = simpleGit(SEMGREP_RULES_DIR);
    await git.pull('origin', 'main');
  }
}

/**
 * Recursively walk semgrep-rules looking for .yaml files and parse them.
 */
function walkRulesDir(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      walkRulesDir(fullPath);
    } else if (entry.isFile() && entry.name.endsWith('.yaml')) {
      parseRuleFile(fullPath);
    }
  }
}

/**
 * Parse a single semgrep YAML file and store the rules in mergedPatterns & mergedRecommendations
 */
function parseRuleFile(filePath) {
  try {
    const fileContents = fs.readFileSync(filePath, 'utf-8');
    const parsed = yaml.load(fileContents);

    // Some semgrep YAML may just be a single "rules:" array, or might have multiple documents, etc.
    if (!parsed || typeof parsed !== 'object') return;

    // Semgrep usually wraps everything in { rules: [...] }
    const rulesArray = Array.isArray(parsed.rules) ? parsed.rules : [];

    for (const ruleObj of rulesArray) {
      if (!ruleObj || !ruleObj.id) {
        continue; // skip if no ID
      }

      // We'll build a unique "key" for your scanner
      const ruleId = ruleObj.id;

      // severity
      let mappedSeverity = 'LOW';
      if (ruleObj.severity && severityMap[ruleObj.severity]) {
        mappedSeverity = severityMap[ruleObj.severity];
      }

      // pattern: This might be a single "pattern", or "patterns", or "pattern-either", or "pattern-regex", etc.
      // We'll do best-effort to store *some* representative pattern string
      let foundPattern = '';
      if (ruleObj.pattern) {
        foundPattern = ruleObj.pattern.toString();
      } else if (Array.isArray(ruleObj.patterns) && ruleObj.patterns.length) {
        // Just join them all with " OR " for simplicity
        foundPattern = ruleObj.patterns.map(p => p.pattern).join(' OR ');
      } else if (ruleObj['pattern-either']) {
        foundPattern = JSON.stringify(ruleObj['pattern-either']);
      } else if (ruleObj['pattern-regex']) {
        foundPattern = ruleObj['pattern-regex'].toString();
      }
      // If none of these fields exist, we'll leave foundPattern = ''

      // description
      const description = ruleObj.message || 'No description';

      // references
      // semgrep often stores references in ruleObj.metadata.references
      let references = [];
      if (ruleObj.metadata && ruleObj.metadata.references) {
        references = ruleObj.metadata.references;
      }

      // We'll store an extremely generic recommendation. 
      // If there's a "fix" or "metadata.fix", etc., you could parse it. 
      // For now, we just say "Review the code. See references."
      let recommendation = 'Review the code and see references for guidance';
      if (ruleObj.metadata && ruleObj.metadata.fix) {
        recommendation = String(ruleObj.metadata.fix);
      }
      
      // Build your pattern object
      mergedPatterns[ruleId] = {
        pattern: foundPattern,
        severity: mappedSeverity,
        description,
        category: ruleObj.metadata?.category || 'General',
        subcategory: ruleObj.metadata?.subcategory || '',
        references
      };

      // Build your recommendation object
      mergedRecommendations[ruleId] = {
        recommendation,
        references,
        cwe: ruleObj.metadata?.cwe || ''
      };
    }
  } catch (err) {
    console.error(`Error parsing ${filePath}:`, err);
  }
}

/**
 * Main workflow
 */
(async function main() {
  try {
    await cloneOrPullSemgrepRules();
    walkRulesDir(SEMGREP_RULES_DIR);

    console.log(`\nFound ${Object.keys(mergedPatterns).length} total Semgrep rules.`);

    // Write them to JSON
    fs.writeJsonSync(PATTERNS_OUTPUT_FILE, mergedPatterns, { spaces: 2 });
    fs.writeJsonSync(RECOMMENDATIONS_OUTPUT_FILE, mergedRecommendations, { spaces: 2 });

    console.log(`\nWrote merged Semgrep Patterns to: ${PATTERNS_OUTPUT_FILE}`);
    console.log(`Wrote merged Semgrep Recommendations to: ${RECOMMENDATIONS_OUTPUT_FILE}`);
    console.log(`\nDone!\n`);
  } catch (err) {
    console.error('Merge process failed:', err);
    process.exit(1);
  }
})();
EOF
/**
# ------------------------------------------------------------------------------
#  Step E: Make it executable & run it
# ------------------------------------------------------------------------------
# chmod +x merge_semgrep_rules.js
# node merge_semgrep_rules.js
*/
