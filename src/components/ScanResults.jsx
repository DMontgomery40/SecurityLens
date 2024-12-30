// ScanResults.jsx

import React, { useState, useEffect } from 'react';
import { patterns, patternCategories, recommendations } from '../lib/patterns';


// Severity sort order
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const codeBlockStyles = {
  pre: {
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
    fontSize: '0.9em',
    lineHeight: '1.5',
    overflowX: 'auto',
    margin: '1em 0'
  }
};

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  if (!results) return null;

  const { findings = {}, summary = {} } = results;

  // Group by (description + severity)
  const groupedFindings = Object.entries(findings).reduce((acc, [type, data]) => {
    const description = data.description || 'No description provided';
    const severity = data.severity || 'LOW';
    const key = `${description}_${severity}`;

    if (!acc[key]) {
      acc[key] = {
        type,
        description,
        severity,
        files: [],
        allLineNumbers: {},
        ...data
      };
    } else {
      // Merge file line data if same description & severity
      Object.entries(data.allLineNumbers || {}).forEach(([file, lines]) => {
        if (!acc[key].allLineNumbers[file]) {
          acc[key].allLineNumbers[file] = lines;
        } else {
          const merged = new Set([...acc[key].allLineNumbers[file], ...lines]);
          acc[key].allLineNumbers[file] = Array.from(merged).sort((a, b) => a - b);
        }
      });
    }
    return acc;
  }, {});

  // Convert to array, gather line counts, etc.
  const vulnerabilities = Object.values(groupedFindings).map((v) => {
    const filesSorted = Object.keys(v.allLineNumbers).sort();
    return { ...v, files: filesSorted };
  });

  // Sort by severity first
  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // For "View by file" grouping
  const fileGrouped = {};
  vulnerabilities.forEach((vuln) => {
    vuln.files.forEach((f) => {
      if (!fileGrouped[f]) fileGrouped[f] = [];
      fileGrouped[f].push({
        ...vuln,
        lineNumbers: vuln.allLineNumbers[f] || []
      });
    });
  });

  // Summary statistics are already provided
  const severityStats = {
    CRITICAL: { uniqueCount: summary.criticalIssues || 0, instanceCount: 0 },
    HIGH: { uniqueCount: summary.highIssues || 0, instanceCount: 0 },
    MEDIUM: { uniqueCount: summary.mediumIssues || 0, instanceCount: 0 },
    LOW: { uniqueCount: summary.lowIssues || 0, instanceCount: 0 }
  };
  vulnerabilities.forEach((vuln) => {
    const sev = vuln.severity;
    // Sum line counts for total "instances"
    let totalLines = 0;
    Object.values(vuln.allLineNumbers).forEach((linesArr) => {
      totalLines += linesArr.length;
    });
    severityStats[sev].instanceCount += totalLines;
  });

  // State for filters
  const [activeSeverity, setActiveSeverity] = useState('ALL'); // or CRITICAL/HIGH...
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('type'); // 'type' or 'file'
  const [showBackToTop, setShowBackToTop] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setShowBackToTop(window.scrollY > 400);
    };
    
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Filter logic: by severity + search
  const filterMatches = (vulnOrFileName, vuln) => {
    // Matches severity?
    if (activeSeverity !== 'ALL' && vuln.severity !== activeSeverity) return false;
    // Matches search?
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    // If a vulnerability, check description + file names
    if (vuln) {
      const desc = vuln.description.toLowerCase();
      if (desc.includes(q)) return true;
      // If any file name includes q
      for (let file of vuln.files) {
        if (file.toLowerCase().includes(q)) return true;
      }
      return false;
    } else {
      // if it's a fileName, check if fileName includes search
      return vulnOrFileName.toLowerCase().includes(q);
    }
  };

  const filteredByType = vulnerabilities.filter((v) => filterMatches(null, v));
  const filteredByFile = Object.entries(fileGrouped)
    .map(([fileName, vulns]) => {
      // filter the vulns for that file
      const fv = vulns.filter((v) => filterMatches(fileName, v));
      return { fileName, vulns: fv };
    })
    .filter((group) => group.vulns.length > 0);

  // Expandable lines component
  const FileLineNumbers = ({ lines }) => {
    const [expanded, setExpanded] = useState(false);
    // Show only first 5 if more than 5
    if (lines.length <= 5) {
      return <span className="text-gray-700">{lines.join(', ')}</span>;
    }
    const visible = expanded ? lines : lines.slice(0, 5);
    return (
      <>
        <span className="text-gray-700">
          {visible.join(', ')}
        </span>
        {!expanded && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="ml-2 text-blue-600 text-xs underline"
          >
            Show {lines.length - 5} more
          </button>
        )}
      </>
    );
  };

  // Vulnerability Card Component
  const VulnerabilityCard = ({ vuln }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    
    // Grab the recommendation
    const rec = recommendations[vuln.type];
    // If we want a pattern display, let's find it from patterns
    let matchedPattern = '';
    let cwe = vuln.cwe || '';

    if (patterns[vuln.type]) {
      matchedPattern = patterns[vuln.type].pattern.toString();
    }

    // Style severity badge
    const severityBadge = {
      CRITICAL: 'bg-gradient-to-r from-red-100 to-red-200 text-red-800 border border-red-200',
      HIGH: 'bg-gradient-to-r from-orange-100 to-orange-200 text-orange-800 border border-orange-200',
      MEDIUM: 'bg-gradient-to-r from-yellow-100 to-yellow-200 text-yellow-800 border border-yellow-200',
      LOW: 'bg-gradient-to-r from-blue-100 to-blue-200 text-blue-800 border border-blue-200'
    }[vuln.severity] || 'bg-gray-100 text-gray-700';

    return (
      <div className="vulnerability-card border border-gray-200 rounded-lg shadow-sm transition-all">
        {/* Clickable Header */}
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full p-4 text-left flex items-center justify-between hover:bg-gray-50"
        >
          <div className="flex-1">
            <span className={`severity-badge text-xs font-semibold px-3 py-1 rounded-full w-fit uppercase ${severityBadge}`}>
              {vuln.severity}
            </span>
            <h3 className="text-lg font-medium mt-2">{vuln.description}</h3>
            <div className="text-sm text-gray-500 mt-1">
              Found in {Object.keys(vuln.allLineNumbers).length} file(s)
            </div>
          </div>
          <svg 
            className={`w-5 h-5 transform transition-transform ${isExpanded ? 'rotate-180' : ''}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </button>

        {/* Expandable Content */}
        {isExpanded && (
          <div className="p-4 border-t border-gray-200">
            {/* File list */}
            <div className="files-list mb-4 text-sm text-gray-700">
              {vuln.files.length > 0 ? (
                <div>Found in {vuln.files.length} file{vuln.files.length > 1 ? 's' : ''}:</div>
              ) : (
                <div>No files recorded.</div>
              )}
              {vuln.files.map((file, idx) => (
                <details
                  key={`${file}-${idx}`}
                  className="file-item border border-gray-200 rounded-md mt-2"
                >
                  <summary className="px-3 py-2 bg-gray-50 rounded-md cursor-pointer">
                    {file}
                  </summary>
                  <div className="file-content p-3 bg-gray-100 rounded-b-md text-sm text-gray-800">
                    Lines: <FileLineNumbers lines={vuln.allLineNumbers[file]} />
                  </div>
                </details>
              ))}
            </div>

            {/* Recommendation section */}
            {rec ? (
              <div className="recommendation bg-gray-50 border border-gray-200 rounded-md p-4 text-sm">
                {/* Split recommendation into sections and handle code blocks specially */}
                {rec.recommendation.split(/(Instead of:|Do:)/).map((section, index) => {
                  if (section === 'Instead of:' || section === 'Do:') {
                    // Return the label
                    return (
                      <div key={index} className="font-medium mt-3 mb-2">
                        {section}
                      </div>
                    );
                  } else if (section.includes('```')) {
                    // Handle code blocks - extract content between ``` marks
                    const code = section.match(/```(?:\w*\n)?([^`]+)```/);
                    return code ? (
                      <pre key={index} className="bg-gray-800 text-gray-100 p-3 rounded-md my-2 overflow-x-auto">
                        <code>{code[1].trim()}</code>
                      </pre>
                    ) : null;
                  } else {
                    // Regular text
                    return (
                      <div
                        key={index}
                        className="prose prose-sm text-gray-800 max-w-none"
                        dangerouslySetInnerHTML={{
                          __html: section
                            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                            .replace(/\n/g, '<br />')
                        }}
                      />
                    );
                  }
                })}
                
                {/* References */}
                {rec.references && rec.references.length > 0 && (
                  <div className="references border-t border-gray-200 mt-3 pt-3">
                    <h4 className="font-medium mb-2">References</h4>
                    <ul className="list-disc pl-5">
                      {rec.references.map((r, i) => (
                        <li key={i}>
                          <a
                            href={r.url}
                            className="text-blue-600 hover:underline"
                            target="_blank"
                            rel="noreferrer"
                          >
                            {r.title || r.url}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {/* Pattern Info (Detection Pattern) */}
                {matchedPattern ? (
                  <div className="pattern-info mt-3 pt-3 border-t border-gray-200">
                    <h4 className="font-medium mb-2">Detection Pattern</h4>
                    <p className="mb-1 text-gray-700 text-sm">
                      This vulnerability was detected using the following pattern:
                    </p>
                    <pre className="bg-white p-2 text-xs text-gray-800 rounded overflow-auto">
                      {matchedPattern}
                    </pre>
                    {vuln.category || vuln.subcategory ? (
                      <p className="text-xs text-gray-600 mt-2">
                        Category: {Object.keys(patternCategories).find(k => patternCategories[k] === vuln.category)} ({vuln.category})<br />
                        Subcategory: {vuln.subcategory}
                      </p>
                    ) : null}
                  </div>
                ) : null}
              </div>
            ) : (
              <div className="bg-gray-50 border border-gray-200 rounded-md p-3 text-sm">
                No recommendation found for "{vuln.type}" type.
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  // Add floating navigation
  const FloatingNav = () => (
    <div className="fixed right-4 top-1/2 transform -translate-y-1/2 bg-white rounded-lg shadow-lg border border-gray-200 p-2 hidden lg:block">
      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
        <button
          key={severity}
          onClick={() => {
            setActiveSeverity(activeSeverity === severity ? 'ALL' : severity);
            // Smooth scroll to first matching result
            const firstResult = document.querySelector(`.${severity.toLowerCase()}`);
            if (firstResult) {
              firstResult.scrollIntoView({ behavior: 'smooth' });
            }
          }}
          className={`flex items-center gap-2 px-3 py-2 rounded-md w-full mb-1 last:mb-0 transition-colors
            ${activeSeverity === severity ? 'bg-gray-100' : 'hover:bg-gray-50'}`}
        >
          <div className={`w-2 h-2 rounded-full ${
            severity === 'CRITICAL' ? 'bg-red-500' :
            severity === 'HIGH' ? 'bg-orange-500' :
            severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-blue-500'
          }`} />
          <span className="text-sm">{severityStats[severity].uniqueCount}</span>
        </button>
      ))}
    </div>
  );

  // UI Rendering
  return (
    <div className="mt-8 relative">
      <div className="scan-results bg-white shadow rounded-lg p-6">
        {/* Summary Cards */}
        <div className="summary-grid grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
            <button
              key={severity}
              type="button"
              onClick={() => setActiveSeverity(activeSeverity === severity ? 'ALL' : severity)}
              className={`summary-card ${severity.toLowerCase()} p-6 rounded-xl border-2 cursor-pointer transition-all transform hover:scale-105 
                ${activeSeverity === severity ? 'border-gray-700 shadow-lg' : 'border-transparent shadow'}
                ${severity === 'CRITICAL' 
                  ? 'bg-gradient-to-br from-red-50 to-red-100 text-red-700'
                  : severity === 'HIGH'
                  ? 'bg-gradient-to-br from-orange-50 to-orange-100 text-orange-700'
                  : severity === 'MEDIUM'
                  ? 'bg-gradient-to-br from-yellow-50 to-yellow-100 text-yellow-700'
                  : 'bg-gradient-to-br from-blue-50 to-blue-100 text-blue-700'
                }`}
            >
              <div className="summary-label text-sm font-semibold mb-2">
                {severity.charAt(0) + severity.slice(1).toLowerCase()}
              </div>
              <div className="summary-numbers flex flex-col gap-1">
                <div className="summary-count text-3xl font-bold">
                  {severityStats[severity].uniqueCount}
                </div>
                <div className="summary-details text-sm opacity-90">
                  Unique Vulnerabilities
                </div>
                <div className="summary-details text-sm opacity-90">
                  {severityStats[severity].instanceCount} Total Instances
                </div>
              </div>
            </button>
          ))}
        </div>

        {/* Cache Notice */}
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

        {/* Toggle Buttons */}
        <div className="view-toggle flex gap-1 bg-gray-200 rounded-md p-1 w-fit mb-4">
          <button
            onClick={() => setViewMode('type')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'type' ? 'bg-white font-medium' : ''
            }`}
          >
            View by Vulnerability Type
          </button>
          <button
            onClick={() => setViewMode('file')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'file' ? 'bg-white font-medium' : ''
            }`}
          >
            View by File
          </button>
        </div>

        {/* Search Bar */}
        <div className="mb-6">
          <input
            type="text"
            placeholder="Search by description or file path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Scan Results */}
        {viewMode === 'type' ? (
          // By Vulnerability Type
          filteredByType.length ? (
            <div className="space-y-4">
              {filteredByType.map((vuln, i) => (
                <VulnerabilityCard key={i} vuln={vuln} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No vulnerabilities found
            </div>
          )
        ) : (
          // By File
          filteredByFile.length ? (
            <div className="space-y-4">
              {filteredByFile.map(({ fileName, vulns }) => (
                <div key={fileName} className="file-view border border-gray-200 rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-3">{fileName}</h3>
                  <div className="vulnerability-list space-y-4">
                    {vulns.map((v, idx) => (
                      <VulnerabilityCard key={`${fileName}-${idx}`} vuln={v} />
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
      <FloatingNav />
      
      {/* Back to Top Button */}
      {showBackToTop && (
        <button
          onClick={scrollToTop}
          className="fixed bottom-8 right-8 bg-blue-600 text-white p-3 rounded-full shadow-lg hover:bg-blue-700 transition-colors"
          aria-label="Back to top"
        >
          <svg 
            className="w-5 h-5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="12" y1="19" x2="12" y2="5"></line>
            <polyline points="5 12 12 5 19 12"></polyline>
          </svg>
        </button>
      )}
    </div>
  );
};
export default ScanResults;
