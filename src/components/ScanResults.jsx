import React, { useState, useEffect } from 'react';
import { patterns, patternCategories, recommendations } from '../lib/patterns';


// Severity sort order
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const ScanResults = ({ files, onRefreshRequest, scanning }) => {
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const runScan = async () => {
    try {
      const scanResults = await scan(files);
      setResults(scanResults);
      setError(null);
    } catch (err) {
      setError(err.message);
      setResults(null);
    }
  };

  useEffect(() => {
    if (files && Object.keys(files).length > 0) {
      runScan();
    }
  }, [files]);

  if (!results) return null;

  const { findings = {}, summary = {} } = results;

  // Convert findings object to array for processing
  const vulnerabilities = Object.entries(findings).map(([type, data]) => {
    const filesSorted = Object.keys(data.allLineNumbers).sort();
    return { 
      ...data,
      type,
      files: filesSorted
    };
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

  // We also want to show "2 Unique Vulnerabilities, 4 Total Instances" in the summary cards
  // Let's count them properly:
  const severityStats = {
    CRITICAL: { uniqueCount: 0, instanceCount: 0 },
    HIGH: { uniqueCount: 0, instanceCount: 0 },
    MEDIUM: { uniqueCount: 0, instanceCount: 0 },
    LOW: { uniqueCount: 0, instanceCount: 0 }
  };
  vulnerabilities.forEach((vuln) => {
    const sev = vuln.severity;
    severityStats[sev].uniqueCount += 1;
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

  // Expandable lines: we'll do a small component
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

  // Renders the big vulnerability card (similar to mockup)
  const VulnerabilityCard = ({ vuln }) => {
    // Grab the recommendation
    const rec = recommendations[vuln.type];
    // If we want a pattern display, let's find it from patterns object
    let matchedPattern = '';
    let cwe = '';
    let catNum = vuln.category || ''; // might be in the data
    let subCat = vuln.subcategory || '';

    // Get pattern info from patterns object
    if (patterns[vuln.type]) {
      matchedPattern = patterns[vuln.type].pattern.toString();
      catNum = patterns[vuln.type].category;
      subCat = patterns[vuln.type].subcategory;
    }
    if (rec && rec.cwe) {
      cwe = rec.cwe; // e.g. "798"
    }

    // We can style severity badge
    const severityBadge = {
      CRITICAL: 'bg-red-100 text-red-800',
      HIGH: 'bg-orange-100 text-orange-800',
      MEDIUM: 'bg-yellow-100 text-yellow-800',
      LOW: 'bg-blue-100 text-blue-800'
    }[vuln.severity] || 'bg-gray-100 text-gray-700';

    return (
      <div className="vulnerability-card border border-gray-200 rounded-lg p-4">
        <div className="vuln-header flex items-start justify-between mb-4">
          <div className="vuln-title flex flex-col gap-2">
            {/* Severity badge + Title */}
            <span className={`severity-badge text-xs font-semibold px-3 py-1 rounded-full w-fit uppercase ${severityBadge}`}>
              {vuln.severity}
            </span>
            <h3 className="text-lg font-medium m-0">{vuln.description}</h3>
            {/* CWE info row */}
            <div className="cve-info text-sm flex gap-4 items-center">
              {cwe ? (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cwe}.html`}
                  className="cve-link text-blue-600 hover:underline flex items-center gap-1"
                  target="_blank"
                  rel="noreferrer"
                >
                  CWE-{cwe}
                </a>
              ) : null}
              {catNum ? (
                <span className="cve-category text-gray-600">
                  Category: {Object.keys(patternCategories).find(k => patternCategories[k] === catNum)} ({catNum})
                </span>
              ) : null}
            </div>
          </div>
        </div>

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
            {/* Why it Matters / What to Do / Example ... We parse the markdown-ish text */}
            {/* We'll split the recommendation into sections if you want, or just show it raw. */}
            <div
              className="prose prose-sm text-gray-800 max-w-none recommendation-section"
              dangerouslySetInnerHTML={{
                __html: rec.recommendation
                  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  .replace(/\n/g, '<br />')
              }}
            />
            {/* References */}
            {rec.references && (
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
                {catNum || subCat ? (
                  <p className="text-xs text-gray-600 mt-2">
                    Category: {Object.keys(patternCategories).find(k => patternCategories[k] === catNum)} ({catNum})<br />
                    Subcategory: {subCat}
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
    );
  };

  // Now we handle UI
  return (
    <div className="mt-8">
      <div className="scan-results bg-white shadow rounded-lg p-6">
        {/* Summary Cards */}
        <div className="summary-grid grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {/* CRITICAL */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`
              summary-card critical p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'CRITICAL' ? 'border-red-700' : 'border-transparent'}
              bg-red-50 text-red-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">Critical</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.CRITICAL.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.CRITICAL.instanceCount} Total Instances
              </div>
            </div>
          </button>

          {/* HIGH */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
            className={`
              summary-card high p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'HIGH' ? 'border-orange-700' : 'border-transparent'}
              bg-orange-50 text-orange-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">High</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.HIGH.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.HIGH.instanceCount} Total Instances
              </div>
            </div>
          </button>

          {/* MEDIUM */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
            className={`
              summary-card medium p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'MEDIUM' ? 'border-yellow-700' : 'border-transparent'}
              bg-yellow-50 text-yellow-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">Medium</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.MEDIUM.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.MEDIUM.instanceCount} Total Instances
              </div>
            </div>
          </button>

          {/* LOW */}
          <button
            type="button"
            onClick={() => setActiveSeverity(activeSeverity === 'LOW' ? 'ALL' : 'LOW')}
            className={`
              summary-card low p-4 rounded-lg border-2 cursor-pointer transition-transform
              ${activeSeverity === 'LOW' ? 'border-blue-700' : 'border-transparent'}
              bg-blue-50 text-blue-700 hover:scale-[1.02]
            `}
          >
            <div className="summary-label text-sm font-semibold mb-1">Low</div>
            <div className="summary-numbers flex flex-col gap-1">
              <div className="summary-count text-2xl font-bold">
                {severityStats.LOW.uniqueCount}
              </div>
              <div className="summary-details text-sm">
                Unique Vulnerabilities
              </div>
              <div className="summary-details text-sm">
                {severityStats.LOW.instanceCount} Total Instances
              </div>
            </div>
          </button>
        </div>

        {/* Show the cache notice */}
        {error && (
          <div className="mb-4 flex items-center justify-between bg-red-50 p-4 rounded-lg">
            <span className="text-red-700">{error}</span>
          </div>
        )}

        {/* Toggle buttons */}
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

        {/* Search bar */}
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
          // By vulnerability
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
          // By file
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
    </div>
  );
};

export default ScanResults;
