import React from 'react';
import { patterns, patternCategories, recommendations } from '../lib/patterns';
import { Shield } from 'lucide-react';
import { type } from 'os';

// Severity sort order
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/**
 * Component to display line numbers with expandable functionality
 */
const FileLineNumbers = ({ vuln, file }) => {
  const [expanded, setExpanded] = React.useState(false);
  
  // For web scans, show the actual code
  if (vuln.scanType === 'web' && vuln.codeLines) {
    const visibleLines = expanded ? vuln.codeLines : vuln.codeLines.slice(0, 3);
    return (
      <div className="mt-2 space-y-2 bg-gray-800 p-3 rounded">
        {visibleLines.map(({ line, code, isMinified, isHtml }) => (
          <div key={line} className="flex items-start space-x-2">
            <span className="text-gray-500 select-none w-12 text-right font-mono">{line}</span>
            <pre 
              className={`text-gray-300 overflow-x-auto font-mono text-sm whitespace-pre-wrap flex-1 ${
                isMinified ? 'bg-gray-900/50 p-2 rounded' : ''
              }`}
              {...(isHtml ? { dangerouslySetInnerHTML: { __html: code } } : { children: code })}
            />
          </div>
        ))}
        {!expanded && vuln.codeLines.length > 3 && (
          <button
            onClick={() => setExpanded(true)}
            className="text-blue-400 text-xs hover:underline mt-2"
          >
            Show {vuln.codeLines.length - 3} more lines
          </button>
        )}
      </div>
    );
  }

  // For local/GitHub scans, show just the line numbers
  const lines = vuln.allLineNumbers[file];
  if (!lines || lines.length === 0) return null;
  
  return (
    <div className="mt-2">
      <span className="text-gray-300">Lines: {lines.join(', ')}</span>
    </div>
  );
};

/**
 * Severity Summary Card Component
 */
const SeveritySummaryCard = ({ severity, count, totalInstances, isActive, onClick }) => {
  const severityStyles = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-blue-500'
  };

  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-lg border-2 transition-transform transform hover:scale-105 ${
        isActive ? 'border-gray-300 shadow-lg' : 'border-transparent shadow'
      } ${severityStyles[severity]} text-white`}
    >
      <div className="text-sm font-semibold mb-1">
        {severity.charAt(0) + severity.slice(1).toLowerCase()}
      </div>
      <div className="text-3xl font-bold">{count}</div>
      <div className="text-sm">Unique Vulnerabilities</div>
      <div className="text-sm mt-1">{totalInstances} Total Instances</div>
    </button>
  );
};

/**
 * Floating Navigation Component for Severity Filters
 */
const FloatingNav = ({ activeSeverity, setActiveSeverity, severityStats }) => (
  <div className="fixed right-4 top-1/2 transform -translate-y-1/2 bg-gray-800 rounded-lg shadow-lg border border-gray-700 p-2 hidden lg:block">
    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
      <button
        key={sev}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setActiveSeverity(activeSeverity === sev ? 'ALL' : sev);
        }}
        className={`flex items-center gap-2 px-3 py-2 rounded-md w-full mb-1 last:mb-0 transition-colors ${
          activeSeverity === sev ? 'bg-gray-700' : 'hover:bg-gray-600'
        }`}
      >
        <div
          className={`w-2 h-2 rounded-full ${
            sev === 'CRITICAL'
              ? 'bg-red-500'
              : sev === 'HIGH'
              ? 'bg-orange-500'
              : sev === 'MEDIUM'
              ? 'bg-yellow-500'
              : 'bg-blue-500'
          }`}
        />
        <span className="text-sm">{severityStats[sev].uniqueCount}</span>
      </button>
    ))}
  </div>
);

/**
 * Vulnerability Card Component
 */
const VulnerabilityCard = ({ vuln, onViewProtection }) => {
  const [isExpanded, setIsExpanded] = React.useState(false);

  // Retrieve recommendation and references
  const rec = recommendations[vuln.type];
  const matchedPattern = patterns[vuln.type] ? patterns[vuln.type].pattern.toString() : '';

  // Style severity badge based on severity
  const severityBadge = {
    CRITICAL: 'bg-red-500 text-white',
    HIGH: 'bg-orange-500 text-white',
    MEDIUM: 'bg-yellow-500 text-gray-800',
    LOW: 'bg-blue-500 text-white'
  }[vuln.severity] || 'bg-gray-500 text-white';

  // Inside the recommendation section
  const formatCodeBlock = (text) => {
    // Use a different delimiter for code blocks, like :::
    return text.replace(
      /:::\s*(\w*)\n([\s\S]*?):::/g,
      '<pre class="bg-gray-800 text-gray-200 p-3 rounded-md my-2"><code>$2</code></pre>'
    );
  };

  return (
    <div className="border border-gray-700 rounded-lg shadow-sm">
      {/* Clickable Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 text-left flex items-center justify-between bg-gray-800 hover:bg-gray-700 transition-colors"
      >
        <div className="flex-1">
          <span className={`text-xs font-semibold py-1 px-2 rounded-full uppercase ${severityBadge}`}>
            {vuln.severity}
          </span>
          <h3 className="text-lg font-medium mt-2">{vuln.description}</h3>
          <div className="text-sm text-gray-400 mt-1">
            Found in {vuln.files.length} file(s)
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
        <div className="p-4 bg-gray-700">
          {/* File list */}
          <div className="files-list mb-4 text-sm text-gray-300">
            {vuln.files.length > 0 ? (
              <div>Found in {vuln.files.length} file{vuln.files.length > 1 ? 's' : ''}:</div>
            ) : (
              <div>No files recorded.</div>
            )}
            {vuln.files.map((file, idx) => (
              <details
                key={`${file}-${idx}`}
                className="file-item border border-gray-600 rounded-md mt-2"
              >
                <summary className="px-3 py-2 bg-gray-800 rounded-t-md cursor-pointer hover:bg-gray-700">
                  {file}
                </summary>
                <div className="p-3 bg-gray-700 rounded-b-md">
                  <FileLineNumbers vuln={vuln} file={file} />
                </div>
              </details>
            ))}
          </div>

          {/* Recommendation Section */}
          {rec ? (
            <div className="recommendation bg-gray-600 border border-gray-500 rounded-md p-4 text-sm">
              {/* Split recommendation into sections and handle code blocks */}
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
                  const codeMatch = section.match(/```[\w]*\n([\s\S]*?)```/);
                  return codeMatch ? (
                    <pre key={index} className="bg-gray-800 text-gray-200 p-3 rounded-md my-2 overflow-x-auto">
                      <code>{codeMatch[1].trim()}</code>
                    </pre>
                  ) : null;
                } else {
                  // Regular text
                  return (
                    <div
                      key={index}
                      className="prose prose-sm text-gray-300 max-w-none"
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
                <div className="references border-t border-gray-500 mt-3 pt-3">
                  <h4 className="font-medium mb-2">References</h4>
                  <ul className="list-disc pl-5">
                    {rec.references.map((r, i) => (
                      <li key={i}>
                        <a
                          href={r.url}
                          className="text-blue-400 underline"
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

              {/* Pattern Info */}
              {matchedPattern && (
                <div className="pattern-info mt-3 pt-3 border-t border-gray-500">
                  <h4 className="font-medium mb-2">Detection Pattern</h4>
                  <pre className="bg-gray-800 p-2 text-xs text-gray-200 rounded overflow-auto">
                    {matchedPattern}
                  </pre>
                  {vuln.category || vuln.subcategory ? (
                    <p className="text-xs text-gray-400 mt-2">
                      Category: {Object.keys(patternCategories).find(k => patternCategories[k] === vuln.category)} ({vuln.category})<br />
                      Subcategory: {vuln.subcategory}
                    </p>
                  ) : null}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-600 border border-gray-500 rounded-md p-3 text-sm">
              No recommendation found for "{vuln.type}" type.
            </div>
          )}
        </div>
      )}

      {/* Add mobile protection guide button */}
      <button 
        className="lg:hidden mt-4 w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
        onClick={() => onViewProtection(vuln)}
      >
        <Shield className="w-4 h-4" />
        View Protection Guide
      </button>
    </div>
  );
};

const ScanResults = ({ 
  viewMode,
  setViewMode,
  searchQuery,
  setSearchQuery,
  activeSeverity,
  setActiveSeverity,
  severityStats,
  filteredByType,
  filteredByFile,
  usedCache,
  scanning,
  onRefreshRequest,
  showBackToTop,
  scrollToTop,
  includeFirmware,
  onViewProtection
}) => {
  return (
    <div className="mt-8 relative" id="scanResults">
      <div
        className="
          bg-gray-800
          rounded-lg
          p-6
          prose prose-invert
          prose-pre:bg-gray-900 
          prose-pre:text-gray-100 
          max-w-none
          sticky top-4
          text-gray-100
        "
      >
        {/* *** Added: Firmware/Binary Analysis Filter *** */}
        <div className="flex items-center mb-6">
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={includeFirmware}
              onChange={(e) => {}} /* Handle firmware filter change if needed */
              className="form-checkbox h-4 w-4 text-blue-600"
              disabled // Disable for now since functionality is not implemented
            />
            <span className="ml-2 text-gray-300">Include Firmware/Binary Analysis</span>
          </label>
          <span className="ml-4 text-xs text-yellow-400">(Coming Soon!)</span>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <SeveritySummaryCard
              key={sev}
              severity={sev}
              count={severityStats[sev].uniqueCount}
              totalInstances={severityStats[sev].instanceCount}
              isActive={activeSeverity === sev}
              onClick={() => setActiveSeverity(activeSeverity === sev ? 'ALL' : sev)}
            />
          ))}
        </div>

        {/* Cache Notice */}
        {usedCache && (
          <div className="mb-4 flex items-center justify-between bg-blue-900/50 p-4 rounded-lg border border-blue-700">
            <span className="text-blue-100">⚡ Results loaded from cache</span>
            <button
              onClick={onRefreshRequest}
              disabled={scanning}
              className={`px-4 py-2 rounded text-sm ${
                scanning
                  ? 'bg-gray-700 cursor-not-allowed text-gray-400'
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
              }`}
            >
              {scanning ? 'Refreshing...' : 'Refresh Scan'}
            </button>
          </div>
        )}

        {/* Toggle Buttons */}
        <div className="flex gap-1 bg-gray-800 rounded-md p-1 w-fit mb-4">
          <button
            onClick={() => setViewMode('type')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'type' ? 'bg-gray-700 text-white font-medium' : 'bg-gray-800 text-gray-300'
            }`}
          >
            View by Vulnerability Type
          </button>
          <button
            onClick={() => setViewMode('file')}
            className={`px-4 py-2 text-sm rounded ${
              viewMode === 'file' ? 'bg-gray-700 text-white font-medium' : 'bg-gray-800 text-gray-300'
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
            className="w-full px-4 py-2 border border-gray-600 rounded-lg bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-100"
          />
        </div>

        {/* Scan Results */}
        {viewMode === 'type' ? (
          filteredByType.length ? (
            <div className="space-y-4">
              {filteredByType.map((vuln, idx) => (
                <VulnerabilityCard 
                  key={idx} 
                  vuln={vuln} 
                  onViewProtection={onViewProtection} 
                />
              ))}
            </div>
          ) : (
            <div className="text-center text-gray-300 py-8 bg-gray-800 rounded-lg border border-gray-700">
              No vulnerabilities found
            </div>
          )
        ) : filteredByFile.length ? (
          <div className="space-y-4">
            {filteredByFile.map(({ fileName, vulns }) => (
              <div key={fileName} className="border border-gray-700 rounded-lg p-4 bg-gray-800">
                <h3 className="text-lg font-semibold mb-3 text-gray-100">{fileName}</h3>
                <div className="space-y-4">
                  {vulns.map((v, idx) => (
                    <VulnerabilityCard key={idx} vuln={v} onViewProtection={onViewProtection} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center text-gray-300 py-8 bg-gray-800 rounded-lg border border-gray-700">
            No vulnerabilities found
          </div>
        )}
      </div>

      <FloatingNav 
        activeSeverity={activeSeverity}
        setActiveSeverity={setActiveSeverity}
        severityStats={severityStats}
      />

      {/* Back to Top Button */}
      {showBackToTop && (
        <button
          onClick={scrollToTop}
          className="fixed bottom-8 right-8 bg-blue-600 text-white p-3 rounded-full shadow-lg hover:bg-blue-700 transition-colors z-50"
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

      <style>
        {`
          .example-block {
            margin: 1rem 0;
            border-radius: 0.5rem;
            overflow: hidden;
          }

          .example-label {
            padding: 0.5rem 1rem;
            font-weight: 500;
            background: rgba(0,0,0,0.2);
          }

          .code-block {
            margin: 0;
            padding: 1rem;
            background: rgba(0,0,0,0.3);
            font-family: monospace;
            font-size: 0.9rem;
            overflow-x: auto;
          }

          .code-block.bad {
            border-left: 4px solid #ef4444;
          }

          .code-block.good {
            border-left: 4px solid #22c55e;
          }
        `}
      </style>
    </div>
  );
};

export default ScanResults;