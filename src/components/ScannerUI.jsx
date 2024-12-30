import React, { useState } from 'react';

// Keep these if you need them in the same file; otherwise import from wherever:
export const patternCategories = {
  CRITICAL_EXECUTION: '94',
  AUTHENTICATION: '287',
  INJECTION: '74',
  CRYPTO_ISSUES: '310',
  MEMORY_BUFFER: '119',
  DATA_PROTECTION: '200',
  INPUT_VALIDATION: '20',
  ERROR_HANDLING: '389',
  ACCESS_CONTROL: '264',
  RESOURCE_MGMT: '399',
  SSRF: '918',
  SESSION_MANAGEMENT: '384'
};

// Example recommendations object, if needed in the same file:
export const recommendations = {
  hardcodedCreds: {
    recommendation: `
      **Why it Matters**: Hardcoded credentials in source code can be found by attackers, 
      giving direct access to privileged resources.

      **What to Do**:
      1. **Use Environment Variables**: ...
      2. **Rotate Credentials**: ...
    `,
    references: [
      {
        title: 'CWE-798: Use of Hard-coded Credentials',
        url: 'https://cwe.mitre.org/data/definitions/798.html'
      }
    ]
  },
  // ... add the rest of your recommendation objects
};

// A helper object for severity ordering
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  if (!results) return null;

  const { findings = {}, summary = {} } = results;

  // Group findings by description + severity (like before)
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
      // Merge file info if same description & severity
      Object.entries(data.allLineNumbers || {}).forEach(([file, lines]) => {
        if (!acc[key].allLineNumbers[file]) {
          acc[key].allLineNumbers[file] = lines;
        } else {
          acc[key].allLineNumbers[file] = [
            ...new Set([...acc[key].allLineNumbers[file], ...lines])
          ].sort((a, b) => a - b);
        }
      });
    }

    return acc;
  }, {});

  // Convert to an array and sort by severity
  const vulnerabilities = Object.values(groupedFindings)
    .map(data => ({
      ...data,
      files: Object.keys(data.allLineNumbers || {}).sort()
    }))
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // We also want the data grouped by file for the “View by File” mode
  // -> That means scanning vulnerabilities for each file
  // -> Then collecting vulnerabilities that appear in that file + line numbers
  const fileGrouped = {};
  vulnerabilities.forEach(vuln => {
    vuln.files.forEach(file => {
      if (!fileGrouped[file]) {
        fileGrouped[file] = [];
      }
      fileGrouped[file].push({
        ...vuln,
        lineNumbers: vuln.allLineNumbers[file] || []
      });
    });
  });

  // State for clickable severity selection, search, and view mode
  const [activeSeverity, setActiveSeverity] = useState('ALL'); // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'ALL'
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('type'); // 'type' or 'file'

  // Filter the vulnerabilities based on activeSeverity & search
  const filteredByType = vulnerabilities.filter(vuln => {
    const matchesSeverity =
      activeSeverity === 'ALL' || vuln.severity === activeSeverity;
    const matchesSearch =
      searchQuery === '' ||
      vuln.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      vuln.files.some(f =>
        f.toLowerCase().includes(searchQuery.toLowerCase())
      );
    return matchesSeverity && matchesSearch;
  });

  // For the “View by File” mode, we need to filter at the file level
  // We'll produce a new structure that only includes files/vulns matching the user filter
  const filteredByFile = Object.entries(fileGrouped)
    .map(([fileName, vulns]) => {
      // Filter each vulnerability in this file by severity + search
      const fileVulns = vulns.filter(vuln => {
        const matchesSeverity =
          activeSeverity === 'ALL' || vuln.severity === activeSeverity;
        const matchesSearch =
          searchQuery === '' ||
          vuln.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
          fileName.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesSeverity && matchesSearch;
      });

      return { fileName, fileVulns };
    })
    .filter(group => group.fileVulns.length > 0);

  // Summaries for the clickable cards
  const totalCritical = summary.criticalIssues || 0;
  const totalHigh = summary.highIssues || 0;
  const totalMed = summary.mediumIssues || 0;
  const totalLow = summary.lowIssues || 0;

  // Helper to apply “selected” style if activeSeverity matches
  const isSelected = sev => activeSeverity === sev;

  return (
    <div className="mt-8">
      {/* Container with white background etc. */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">Scan Results</h2>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <button
            type="button"
            onClick={() => setActiveSeverity('CRITICAL')}
            className={`p-4 rounded-lg border-2 transition-transform ${
              isSelected('CRITICAL') ? 'border-red-700' : 'border-transparent'
            } bg-red-50 text-red-700 hover:scale-[1.02]`}
          >
            <div className="font-semibold">Critical</div>
            <div className="text-2xl">{totalCritical}</div>
          </button>

          <button
            type="button"
            onClick={() => setActiveSeverity('HIGH')}
            className={`p-4 rounded-lg border-2 transition-transform ${
              isSelected('HIGH') ? 'border-orange-700' : 'border-transparent'
            } bg-orange-50 text-orange-700 hover:scale-[1.02]`}
          >
            <div className="font-semibold">High</div>
            <div className="text-2xl">{totalHigh}</div>
          </button>

          <button
            type="button"
            onClick={() => setActiveSeverity('MEDIUM')}
            className={`p-4 rounded-lg border-2 transition-transform ${
              isSelected('MEDIUM') ? 'border-yellow-700' : 'border-transparent'
            } bg-yellow-50 text-yellow-700 hover:scale-[1.02]`}
          >
            <div className="font-semibold">Medium</div>
            <div className="text-2xl">{totalMed}</div>
          </button>

          <button
            type="button"
            onClick={() => setActiveSeverity('LOW')}
            className={`p-4 rounded-lg border-2 transition-transform ${
              isSelected('LOW') ? 'border-blue-700' : 'border-transparent'
            } bg-blue-50 text-blue-700 hover:scale-[1.02]`}
          >
            <div className="font-semibold">Low</div>
            <div className="text-2xl">{totalLow}</div>
          </button>
        </div>

        {/* Cache Notice (unchanged) */}
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

        {/* View Toggle */}
        <div className="flex items-center gap-2 bg-gray-200 rounded-md p-1 w-fit mb-6">
          <button
            type="button"
            onClick={() => setViewMode('type')}
            className={`px-4 py-2 rounded ${
              viewMode === 'type' ? 'bg-white font-medium' : ''
            }`}
          >
            View by Vulnerability Type
          </button>
          <button
            type="button"
            onClick={() => setViewMode('file')}
            className={`px-4 py-2 rounded ${
              viewMode === 'file' ? 'bg-white font-medium' : ''
            }`}
          >
            View by File
          </button>
        </div>

        {/* Search Input */}
        <div className="mb-6">
          <input
            type="text"
            placeholder="Search by description or file path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Results Display */}
        {viewMode === 'type' ? (
          <>
            {/* Vuln-by-Type View */}
            {filteredByType.length > 0 ? (
              <div className="space-y-4">
                {filteredByType.map((finding, index) => {
                  const recommendation = recommendations[finding.type];
                  return (
                    <div
                      key={index}
                      className="border border-gray-200 rounded-lg p-4"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <h3 className="font-semibold text-lg">
                            {finding.description}
                          </h3>
                          <div className="mt-2 text-sm text-gray-700">
                            <strong>Files:</strong>{' '}
                            {finding.files.map((file, i) => (
                              <span key={i} className="mr-2">
                                {file} (lines:{' '}
                                {finding.allLineNumbers[file].join(', ')})
                              </span>
                            ))}
                          </div>
                        </div>
                        <div
                          className={`ml-4 px-3 py-1 rounded-full text-sm font-medium whitespace-nowrap ${
                            finding.severity === 'CRITICAL'
                              ? 'bg-red-100 text-red-800'
                              : finding.severity === 'HIGH'
                              ? 'bg-orange-100 text-orange-800'
                              : finding.severity === 'MEDIUM'
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-blue-100 text-blue-800'
                          }`}
                        >
                          {finding.severity}
                        </div>
                      </div>

                      {/* Recommendation details */}
                      {recommendation && (
                        <div className="mt-4 bg-gray-50 rounded p-3 text-sm text-gray-700">
                          <div
                            className="prose prose-sm max-w-none"
                            dangerouslySetInnerHTML={{
                              __html: recommendation.recommendation
                                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                                .replace(/\n/g, '<br />')
                            }}
                          />
                          {recommendation.references && (
                            <div className="mt-2">
                              <strong>References:</strong>
                              <ul className="list-disc pl-5 mt-1">
                                {recommendation.references.map((ref, idx) => (
                                  <li key={idx}>
                                    <a
                                      href={ref.url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-blue-600 hover:underline"
                                    >
                                      {ref.title || ref.url}
                                    </a>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                No vulnerabilities found
              </div>
            )}
          </>
        ) : (
          <>
            {/* View by File */}
            {filteredByFile.length > 0 ? (
              <div className="space-y-4">
                {filteredByFile.map(({ fileName, fileVulns }) => (
                  <div
                    key={fileName}
                    className="border border-gray-200 rounded-lg p-4"
                  >
                    <h3 className="text-lg font-semibold mb-2">{fileName}</h3>
                    <ul className="space-y-2">
                      {fileVulns.map((vuln, i) => {
                        const recommendation = recommendations[vuln.type];
                        return (
                          <li
                            key={`${fileName}-${i}`}
                            className="bg-gray-50 rounded p-3"
                          >
                            <div className="flex items-start justify-between">
                              <div>
                                <p className="font-medium text-sm">
                                  {vuln.description}
                                </p>
                                <p className="text-xs text-gray-600">
                                  Lines: {vuln.lineNumbers.join(', ')}
                                </p>
                              </div>
                              <span
                                className={`ml-4 px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap ${
                                  vuln.severity === 'CRITICAL'
                                    ? 'bg-red-100 text-red-800'
                                    : vuln.severity === 'HIGH'
                                    ? 'bg-orange-100 text-orange-800'
                                    : vuln.severity === 'MEDIUM'
                                    ? 'bg-yellow-100 text-yellow-800'
                                    : 'bg-blue-100 text-blue-800'
                                }`}
                              >
                                {vuln.severity}
                              </span>
                            </div>
                            {recommendation && (
                              <div className="mt-3 bg-white rounded p-3 text-sm text-gray-700">
                                <div
                                  className="prose prose-sm max-w-none"
                                  dangerouslySetInnerHTML={{
                                    __html: recommendation.recommendation
                                      .replace(
                                        /\*\*(.*?)\*\*/g,
                                        '<strong>$1</strong>'
                                      )
                                      .replace(/\n/g, '<br />')
                                  }}
                                />
                                {recommendation.references && (
                                  <div className="mt-2">
                                    <strong>References:</strong>
                                    <ul className="list-disc pl-5 mt-1">
                                      {recommendation.references.map(
                                        (ref, idx) => (
                                          <li key={idx}>
                                            <a
                                              href={ref.url}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="text-blue-600 hover:underline"
                                            >
                                              {ref.title || ref.url}
                                            </a>
                                          </li>
                                        )
                                      )}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                No vulnerabilities found
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default ScanResults;
