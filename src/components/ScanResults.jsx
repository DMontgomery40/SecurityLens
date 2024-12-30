import React, { useState } from 'react';
import { patternCategories, recommendations } from './patterns';

// Severity sort order
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

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

  const vulnerabilities = Object.values(groupedFindings).map((v) => {
    const filesSorted = Object.keys(v.allLineNumbers).sort();
    return { ...v, files: filesSorted };
  });

  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

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

  const severityStats = {
    CRITICAL: { uniqueCount: summary.criticalIssues || 0, instanceCount: 0 },
    HIGH: { uniqueCount: summary.highIssues || 0, instanceCount: 0 },
    MEDIUM: { uniqueCount: summary.mediumIssues || 0, instanceCount: 0 },
    LOW: { uniqueCount: summary.lowIssues || 0, instanceCount: 0 }
  };
  vulnerabilities.forEach((vuln) => {
    const sev = vuln.severity;
    let totalLines = 0;
    Object.values(vuln.allLineNumbers).forEach((linesArr) => {
      totalLines += linesArr.length;
    });
    severityStats[sev].instanceCount += totalLines;
  });

  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('type');

  const filterMatches = (vulnOrFileName, vuln) => {
    if (activeSeverity !== 'ALL' && vuln.severity !== activeSeverity) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    if (vuln) {
      const desc = vuln.description.toLowerCase();
      if (desc.includes(q)) return true;
      for (let file of vuln.files) {
        if (file.toLowerCase().includes(q)) return true;
      }
      return false;
    } else {
      return vulnOrFileName.toLowerCase().includes(q);
    }
  };

  const filteredByType = vulnerabilities.filter((v) => filterMatches(null, v));
  const filteredByFile = Object.entries(fileGrouped)
    .map(([fileName, vulns]) => {
      const fv = vulns.filter((v) => filterMatches(fileName, v));
      return { fileName, vulns: fv };
    })
    .filter((group) => group.vulns.length > 0);

  const FileLineNumbers = ({ lines }) => {
    const [expanded, setExpanded] = useState(false);
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

  const VulnerabilityCard = ({ vuln }) => {
    const rec = recommendations[vuln.type];
    let matchedPattern = '';
    let cwe = vuln.cwe || '';

    if (patterns[vuln.type]) {
      matchedPattern = patterns[vuln.type].pattern.toString();
    }

    const severityBadge = {
      CRITICAL: 'bg-red-100 text-red-800',
      HIGH: 'bg-orange-100 text-orange-800',
      MEDIUM: 'bg-yellow-100 text-yellow-800',
      LOW: 'bg-blue-100 text-blue-800'
    }[vuln.severity] || 'bg-gray-100 text-gray-700';

    return (
      <div className="vulnerability-card border border-gray-200 rounded-lg p-4 shadow-sm">
        <div className="vuln-header flex items-start justify-between mb-4">
          <div className="vuln-title flex flex-col gap-2">
            <span className={`severity-badge text-xs font-semibold px-3 py-1 rounded-full w-fit uppercase ${severityBadge}`}>
              {vuln.severity}
            </span>
            <h3 className="text-lg font-medium m-0">{vuln.description}</h3>
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
              {vuln.category ? (
                <span className="cve-category text-gray-600">
                  Category: {Object.keys(patternCategories).find(k => patternCategories[k] === vuln.category)} ({vuln.category})
                </span>
              ) : null}
            </div>
          </div>
        </div>

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

        {rec ? (
          <div className="recommendation bg-gray-50 border border-gray-200 rounded-md p-4 text-sm">
            <div
              className="prose prose-sm text-gray-800 max-w-none recommendation-section"
              dangerouslySetInnerHTML={{
                __html: rec.recommendation
                  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  .replace(/## (.*?)\n/g, '<h4>$1</h4>')
                  .replace(/\n/g, '<br />')
              }}
            />
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
    );
  };

  return (
      <div className="mt-8">
        <div className="scan-results bg-white shadow rounded-lg p-6">
          <div className="summary-grid grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
              <button
                key={severity}
                type="button"
                onClick={() => setActiveSeverity(activeSeverity === severity ? 'ALL' : severity)}
                className={`summary-card ${severity.toLowerCase()} p-4 rounded-lg border-2 cursor-pointer transition-transform
                  ${
                    activeSeverity === severity
                      ? `border-${severity.toLowerCase()}-700`
                      : 'border-transparent'
                  }
                  ${
                    severity === 'CRITICAL'
                      ? 'bg-red-50 text-red-700'
                      : severity === 'HIGH'
                      ? 'bg-orange-50 text-orange-700'
                      : severity === 'MEDIUM'
                      ? 'bg-yellow-50 text-yellow-700'
                      : 'bg-blue-50 text-blue-700'
                  } hover:scale-[1.02]`}
              >
                <div className="summary-label text-sm font-semibold mb-1">
                  {severity.charAt(0) + severity.slice(1).toLowerCase()}
                </div>
                <div className="summary-numbers flex flex-col gap-1">
                  <div className="summary-count text-2xl font-bold">
                    {severityStats[severity].uniqueCount}
                  </div>
                  <div className="summary-details text-sm">
                    Unique Vulnerabilities
                  </div>
                  <div className="summary-details text-sm">
                    {severityStats[severity].instanceCount} Total Instances
                  </div>
                </div>
              </button>
            ))}
          </div>

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

          <div className="mb-6">
            <input
              type="text"
              placeholder="Search by description or file path..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {viewMode === 'type' ? (
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