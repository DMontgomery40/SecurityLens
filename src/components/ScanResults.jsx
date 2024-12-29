import React, { useState } from 'react';
import { corePatterns, enhancedPatterns, recommendations } from '../lib/patterns';

// Provide your patternCategories if you need them
import { patternCategories } from '../lib/patterns';

const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

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

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  if (!results) return null;

  const { findings = {}, summary = {} } = results;

  // Convert the "findings" object to an array
  // e.g. { hardcodedCreds: {...}, xssVulnerability: {...} } => [ {...}, {...} ]
  const vulnerabilities = Object.values(findings);

  // Sort them by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
  vulnerabilities.sort((a, b) => {
    const aSev = a.severity || 'LOW';
    const bSev = b.severity || 'LOW';
    return severityOrder[aSev] - severityOrder[bSev];
  });

  // For "View by file" grouping
  // Each vulnerability object has: allLineNumbers: { filename: [lines], ... }
  const fileGrouped = {};
  vulnerabilities.forEach((v) => {
    Object.entries(v.allLineNumbers || {}).forEach(([filename, lines]) => {
      if (!fileGrouped[filename]) fileGrouped[filename] = [];
      // We push an object containing the vulnerability info plus the lines
      fileGrouped[filename].push({
        ...v,
        lines
      });
    });
  });

  // Keep track of active filters
  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('type'); // or 'file'

  // Filter function
  function matchesFilter(vulnOrFile, vulnObj) {
    // Severity
    if (activeSeverity !== 'ALL' && vulnObj.severity !== activeSeverity) {
      return false;
    }
    // Search
    if (searchQuery) {
      const lcSearch = searchQuery.toLowerCase();
      const inDescription = vulnObj.description?.toLowerCase()?.includes(lcSearch);
      const inFile = Object.keys(vulnObj.allLineNumbers || {})
        .some(fn => fn.toLowerCase().includes(lcSearch));
      return inDescription || inFile;
    }
    return true;
  }

  const filteredByType = vulnerabilities.filter((v) => matchesFilter(null, v));
  const filteredByFile = Object.entries(fileGrouped)
    .map(([filename, vulns]) => ({
      filename,
      vulns: vulns.filter((v) => matchesFilter(filename, v))
    }))
    .filter(group => group.vulns.length > 0);

  // Helper to get the code pattern from core/enhanced patterns
  function getRegexPattern(vulnType) {
    if (corePatterns[vulnType]) return corePatterns[vulnType].pattern?.toString() || '';
    if (enhancedPatterns[vulnType]) return enhancedPatterns[vulnType].pattern?.toString() || '';
    return '';
  }

  // Helper for category name
  function getCategoryName(catNum) {
    const foundKey = Object.keys(patternCategories).find(
      (k) => patternCategories[k] === catNum
    );
    return foundKey || catNum || '';
  }

  // Renders the "Vulnerability card" with Why it matters, references, etc.
  const VulnerabilityCard = ({ vuln }) => {
    const { severity = 'LOW', description, type, category, subcategory } = vuln;
    const theme = formatSeverity(severity);

    // If we have a recommendation that matches the type
    const rec = recommendations[type] || {};
    const cwe = rec.cwe;
    const detectionPattern = getRegexPattern(type) || '';

    // For “Similar Vulnerability Example” (if your data has it)
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
            {description || 'Unknown Issue'}
          </h3>

          {/* Top-level info row (CWE, category) */}
          <div className="text-sm text-gray-500 flex gap-3">
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
              <span>
                Subcategory: {subcategory}
              </span>
            )}
          </div>
        </div>

        {/* Impacted Files list */}
        <div className="mb-4">
          {Object.keys(vuln.allLineNumbers).map((file) => (
            <details
              key={file}
              className="mb-2 border border-gray-200 rounded"
            >
              <summary className="cursor-pointer px-3 py-2 bg-gray-50 rounded">
                {file} (Lines: {vuln.allLineNumbers[file].length})
              </summary>
              <div className="bg-white px-3 py-2 text-sm text-gray-700">
                {vuln.allLineNumbers[file].join(', ')}
              </div>
            </details>
          ))}
        </div>

        {/* Recommendation Section */}
        {rec.recommendation ? (
          <div className="bg-gray-50 border border-gray-200 rounded-md p-4 text-sm">
            {/* “Why it Matters” / “What to Do” / “Example” etc. as raw HTML or markdown-ish */}
            <div
              className="prose prose-sm"
              dangerouslySetInnerHTML={{
                __html: rec.recommendation
                  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  .replace(/\n/g, '<br/>')
              }}
            />

            {/* “Similar Vulnerability Example” if you want it collapsible */}
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
            {Array.isArray(rec.references) && rec.references.length > 0 && (
              <div className="mt-3 pt-3 border-t border-gray-200">
                <h4 className="font-semibold mb-1">References:</h4>
                <ul className="list-disc list-inside">
                  {rec.references.map((ref, i) => (
                    <li key={i}>
                      <a
                        href={ref.url}
                        className="text-blue-600 hover:underline"
                        target="_blank"
                        rel="noreferrer"
                      >
                        {ref.title || ref.url}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Detection Pattern */}
            {detectionPattern && (
              <div className="mt-3 pt-3 border-t border-gray-200">
                <h4 className="font-semibold mb-1">Detection Pattern</h4>
                <pre className="bg-gray-900 text-gray-100 p-2 rounded text-xs overflow-auto">
                  {detectionPattern}
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

  // Summaries for each severity (like “2 Unique Vulns, 4 Total Instances”)
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const severityStats = {
    CRITICAL: { unique: 0, instances: 0 },
    HIGH: { unique: 0, instances: 0 },
    MEDIUM: { unique: 0, instances: 0 },
    LOW: { unique: 0, instances: 0 }
  };

  vulnerabilities.forEach((v) => {
    const s = v.severity || 'LOW';
    if (!severityStats[s]) {
      severityStats[s] = { unique: 0, instances: 0 };
    }
    severityStats[s].unique += 1;
    // Count total occurrences by summing line counts
    let totalLines = 0;
    Object.values(v.allLineNumbers || {}).forEach((linesArr) => {
      totalLines += linesArr.length;
    });
    severityStats[s].instances += totalLines;
  });

  return (
    <div className="mt-8">
      <div className="bg-white shadow rounded-lg p-6">
        {/* Summary row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {severities.map((sev) => {
            const theme = formatSeverity(sev);
            const active = activeSeverity === sev;
            return (
              <button
                key={sev}
                type="button"
                onClick={() =>
                  setActiveSeverity(active ? 'ALL' : sev)
                }
                className={`p-4 rounded-lg border-2 transition-transform
                text-left ${theme.bg} ${theme.text}
                ${
                  active
                    ? `border-2 ${theme.border}`
                    : 'border-transparent'
                }
                hover:scale-[1.02]`}
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

        {/* Show the cache notice */}
        {usedCache && (
          <div className="mb-4 flex items-center justify-between bg-blue-50 p-4 rounded-lg">
            <span className="text-blue-700">
              ⚡ Results loaded from cache
            </span>
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

        {/* Toggle buttons for “View by Type” vs “View by File” */}
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
          filteredByType.length ? (
            <div className="space-y-6">
              {filteredByType.map((v, idx) => (
                <VulnerabilityCard key={idx} vuln={v} />
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
                    {vulns.map((v, idx) => (
                      <VulnerabilityCard key={idx} vuln={v} />
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
