import React, { useState } from 'react';
import { corePatterns, enhancedPatterns, recommendations, patternCategories } from '../lib/patterns';

// This object tells us the display order for severities:
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// Simple function to style each severity’s color:
function formatSeverity(sev) {
  switch (sev) {
    case 'CRITICAL':
      return { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-700' };
    case 'HIGH':
      return { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-700' };
    case 'MEDIUM':
      return { bg: 'bg-yellow-50', text: 'text-yellow-700', border: 'border-yellow-700' };
    case 'LOW':
      return { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-700' };
    default:
      return { bg: 'bg-gray-50', text: 'text-gray-700', border: 'border-gray-700' };
  }
}

// Utility to unify each vulnerability’s core data (description, severity, etc.)
function unifyVulnerabilityData(finding) {
  // Identify the “type” (e.g., “hardcodedCreds”, “sqlInjection”)
  const { type } = finding;

  // Retrieve the official pattern definition from core/enhanced
  const patternInfo = { ...corePatterns, ...enhancedPatterns }[type];
  if (!patternInfo) {
    // fallback if no known pattern:
    return {
      type,
      severity: finding.severity || 'LOW',
      description: finding.description || 'No description provided',
      category: finding.category || '',
      subcategory: finding.subcategory || ''
    };
  }

  // Use the standardized severity, description, category, subcategory from pattern info:
  return {
    type,
    severity: patternInfo.severity || finding.severity || 'LOW',
    description: patternInfo.description || finding.description || 'No description provided',
    category: patternInfo.category || finding.category || '',
    subcategory: patternInfo.subcategory || finding.subcategory || ''
  };
}

// For displaying category codes (e.g., “Authentication (287)”) neatly
function getCategoryName(catNumber) {
  const foundKey = Object.keys(patternCategories).find(k => patternCategories[k] === catNumber);
  return foundKey || catNumber || '';
}

// The main component
const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  // If no results, return nothing
  if (!results) return null;

  const { findings = [], summary = {} } = results;
  // “findings” might be an array or an object. If it’s an object-of-objects, convert to array:
  // Some code bases do `Object.values(findings)`, but it depends on how your backend returns it.
  let rawFindingsArray = Array.isArray(findings)
    ? findings
    : Object.values(findings);

  // Step 1: Group everything by “type” so each vulnerability pattern is only one card
  const groupedFindings = rawFindingsArray.reduce((acc, singleFinding) => {
    const typeKey = singleFinding.type;  // e.g. "hardcodedCreds"
    if (!typeKey) return acc; // ignore if no type

    // If we haven't started a group for this type, initialize it
    if (!acc[typeKey]) {
      // unify the base data (severity, description, category, etc.)
      const unifiedData = unifyVulnerabilityData(singleFinding);
      acc[typeKey] = {
        ...unifiedData,
        allLineNumbers: {},
        totalOccurrences: 0,  // sum of all pattern matches
      };
    }

    // Merge line numbers
    const filePath = singleFinding.file || 'Unknown file';
    // If the scanning logic gave us .lineNumbers, merge them
    const lines = singleFinding.lineNumbers || [];
    if (!acc[typeKey].allLineNumbers[filePath]) {
      acc[typeKey].allLineNumbers[filePath] = [];
    }
    acc[typeKey].allLineNumbers[filePath].push(...lines);

    // Increment occurrences
    acc[typeKey].totalOccurrences += singleFinding.occurrences || lines.length || 1;

    return acc;
  }, {});

  // Convert that grouped object to an array for easy sorting & display:
  const vulnerabilities = Object.values(groupedFindings);

  // Sort them by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
  vulnerabilities.sort((a, b) => {
    const aSev = a.severity || 'LOW';
    const bSev = b.severity || 'LOW';
    return severityOrder[aSev] - severityOrder[bSev];
  });

  // Next, we want to do a severity summary, so we’ll iterate:
  const severityStats = {
    CRITICAL: { unique: 0, instances: 0 },
    HIGH: { unique: 0, instances: 0 },
    MEDIUM: { unique: 0, instances: 0 },
    LOW: { unique: 0, instances: 0 }
  };
  vulnerabilities.forEach((v) => {
    const s = v.severity || 'LOW';
    if (!severityStats[s]) severityStats[s] = { unique: 0, instances: 0 };
    severityStats[s].unique += 1;

    // For “instances,” we sum up all lineNumbers
    let totalLines = 0;
    Object.values(v.allLineNumbers).forEach(linesArr => {
      totalLines += linesArr.length;
    });
    severityStats[s].instances += totalLines;
  });

  // State for toggling “View by Type” vs “View by File”
  const [viewMode, setViewMode] = useState('type'); // 'type' or 'file'
  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // We also can group vulnerabilities by file. Let’s do that:
  const fileGrouped = {};
  vulnerabilities.forEach((v) => {
    Object.entries(v.allLineNumbers).forEach(([filename, lines]) => {
      if (!fileGrouped[filename]) fileGrouped[filename] = [];
      fileGrouped[filename].push({
        ...v,
        lines
      });
    });
  });

  // Filter logic
  function matchesFilter(vuln) {
    if (activeSeverity !== 'ALL' && vuln.severity !== activeSeverity) {
      return false;
    }
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    // Check the description, plus any file paths
    if (vuln.description?.toLowerCase().includes(q)) return true;
    // Check the file paths in allLineNumbers
    for (const filePath of Object.keys(vuln.allLineNumbers)) {
      if (filePath.toLowerCase().includes(q)) return true;
    }
    return false;
  }

  const filteredByType = vulnerabilities.filter(matchesFilter);
  const filteredByFile = Object.entries(fileGrouped)
    .map(([filename, vulns]) => ({
      filename,
      vulns: vulns.filter(matchesFilter),
    }))
    .filter((group) => group.vulns.length > 0);

  // Helper to get the “detection pattern” from core/enhanced by type
  function getDetectionPattern(vulnType) {
    const patternObj = { ...corePatterns, ...enhancedPatterns }[vulnType];
    return patternObj?.pattern?.toString() || '';
  }

  // The big “Vulnerability Card”
  const VulnerabilityCard = ({ vuln }) => {
    const { type, severity, description, category, subcategory, allLineNumbers } = vuln;
    const theme = formatSeverity(severity);

    const rec = recommendations[type] || {};
    const cwe = rec.cwe;
    const detectionRegex = getDetectionPattern(type);

    // Expandable “Similar Vulnerability Example” if you want it
    const [showSimilar, setShowSimilar] = useState(false);

    return (
      <div className="border border-gray-200 rounded-lg p-4 shadow-sm">
        {/* Severity + Title */}
        <div className="flex flex-col gap-2 mb-4">
          <span
            className={`inline-block px-3 py-1 text-xs font-semibold uppercase rounded-full w-fit ${theme.bg} ${theme.text}`}
          >
            {severity}
          </span>
          <h3 className="text-lg font-semibold text-gray-900 m-0">
            {description || 'No description'}
          </h3>
          {/* Show CWE, Category, Subcategory */}
          <div className="text-sm text-gray-600 flex flex-wrap gap-4">
            {cwe && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${cwe}.html`}
                target="_blank"
                rel="noreferrer"
                className="text-blue-600 hover:underline"
              >
                CWE-{cwe}
              </a>
            )}
            {category && (
              <span>
                Category: {getCategoryName(category)} ({category})
              </span>
            )}
            {subcategory && (
              <span>Subcategory: {subcategory}</span>
            )}
          </div>
        </div>

        {/* Impacted Files list */}
        <div className="mb-4">
          {Object.entries(allLineNumbers).map(([file, lines]) => (
            <details
              key={file}
              className="mb-2 border border-gray-200 rounded"
            >
              <summary className="cursor-pointer px-3 py-2 bg-gray-50 rounded select-none">
                {file} (Lines: {lines.length})
              </summary>
              <div className="bg-white px-3 py-2 text-sm text-gray-700">
                {lines.join(', ')}
              </div>
            </details>
          ))}
        </div>

        {/* Recommendation Section */}
        {rec.recommendation ? (
          <div className="bg-gray-50 border border-gray-200 rounded-md p-4 text-sm">
            <div
              className="prose prose-sm"
              dangerouslySetInnerHTML={{
                __html: rec.recommendation
                  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  .replace(/\n/g, '<br/>')
              }}
            />
            {/* Similar example, if present */}
            {rec.similarVulnExample && (
              <div className="mt-3">
                <button
                  onClick={() => setShowSimilar(!showSimilar)}
                  className="text-blue-600 underline text-sm"
                >
                  {showSimilar ? 'Hide' : 'Show'} Similar Vulnerability Example
                </button>
                {showSimilar && (
                  <div className="mt-2 p-3 border border-gray-200 bg-white rounded text-sm text-gray-800">
                    {rec.similarVulnExample}
                  </div>
                )}
              </div>
            )}
            {/* References */}
            {!!rec.references?.length && (
              <div className="mt-3 pt-3 border-t border-gray-200">
                <h4 className="font-semibold mb-1">References:</h4>
                <ul className="list-disc list-inside">
                  {rec.references.map((r, i) => (
                    <li key={i}>
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-600 hover:underline"
                      >
                        {r.title || r.url}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {/* Detection Pattern */}
            {detectionRegex && (
              <div className="mt-3 pt-3 border-t border-gray-200">
                <h4 className="font-semibold mb-1">Detection Pattern</h4>
                <pre className="bg-gray-900 text-gray-100 p-2 rounded text-xs overflow-auto">
                  {detectionRegex}
                </pre>
              </div>
            )}
          </div>
        ) : (
          <div className="text-sm text-gray-600 italic">
            No specific recommendation found for <code>{type}</code>.
          </div>
        )}
      </div>
    );
  };

  // The severities we care about, in a stable order
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="mt-8">
      <div className="bg-white shadow rounded-lg p-6">
        {/* Summary cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {severities.map(sev => {
            const theme = formatSeverity(sev);
            const active = activeSeverity === sev;
            return (
              <button
                key={sev}
                type="button"
                onClick={() => setActiveSeverity(active ? 'ALL' : sev)}
                className={`
                  p-4 rounded-lg border-2 transition-transform text-left
                  ${theme.bg} ${theme.text} 
                  ${active ? theme.border : 'border-transparent'}
                  hover:scale-[1.02]
                `}
              >
                <div className="text-sm font-semibold mb-1 capitalize">
                  {sev.charAt(0) + sev.slice(1).toLowerCase()}
                </div>
                <div className="text-2xl font-bold">
                  {severityStats[sev].unique}
                </div>
                <div className="text-sm">Unique Vulnerabilities</div>
                <div className="text-sm">
                  {severityStats[sev].instances} Total Instances
                </div>
              </button>
            );
          })}
        </div>

        {/* If from cache, let them refresh */}
        {usedCache && (
          <div className="mb-4 flex items-center justify-between bg-blue-50 p-4 rounded-lg">
            <span className="text-blue-700">⚡ Results loaded from cache</span>
            <button
              onClick={onRefreshRequest}
              disabled={scanning}
              className={`px-4 py-2 rounded text-sm ${
                scanning
                  ? 'bg-gray-300 cursor-not-allowed'
                  : 'bg-blue-500 hover:bg-blue-600 text-white'
              }`}
            >
              {scanning ? 'Refreshing...' : 'Refresh Scan'}
            </button>
          </div>
        )}

        {/* View mode toggles */}
        <div className="flex gap-1 bg-gray-200 rounded-md p-1 w-fit mb-4">
          <button
            onClick={() => setViewMode('type')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'type' ? 'bg-white font-semibold' : ''
            }`}
          >
            View by Vulnerability Type
          </button>
          <button
            onClick={() => setViewMode('file')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'file' ? 'bg-white font-semibold' : ''
            }`}
          >
            View by File
          </button>
        </div>

        {/* Search box */}
        <div className="mb-6">
          <input
            type="text"
            placeholder="Search by description or file path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Actual results */}
        {viewMode === 'type' ? (
          // By type
          filteredByType.length ? (
            <div className="space-y-6">
              {filteredByType.map((vuln, idx) => (
                <VulnerabilityCard key={idx} vuln={vuln} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No vulnerabilities found
            </div>
          )
        ) : (
          // By file
          filteredByFile.length ? (
            <div className="space-y-6">
              {filteredByFile.map(({ filename, vulns }) => (
                <div
                  key={filename}
                  className="border border-gray-200 rounded-lg p-4"
                >
                  <h3 className="text-lg font-semibold mb-3">
                    {filename}
                  </h3>
                  <div className="space-y-4">
                    {vulns.map((vuln, idx) => (
                      <VulnerabilityCard key={idx} vuln={vuln} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No vulnerabilities found
            </div>
          )
        )}
      </div>
    </div>
  );
};

export default ScanResults;
