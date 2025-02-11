import React from 'react';
import { patterns, patternCategories, recommendations } from '../lib/patterns';
import { FloatingNav } from './FloatingNav';
import { SeveritySummaryCard } from './SeveritySummaryCard';
import { vulnerabilityGuides } from '../lib/proactiveControlsData';
import { Shield } from 'lucide-react';

/**
 * Display line numbers with possible code snippet expansion.
 */
const FileLineNumbers = ({ vuln, file }) => {
  const [expanded, setExpanded] = React.useState(false);
  
  // If it's a "web" type vulnerability with actual code lines
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

  // For local/GitHub scans, just show "Lines: X"
  const lines = vuln.allLineNumbers[file];
  if (!lines || lines.length === 0) return null;
  
  return (
    <div className="mt-2">
      <span className="text-gray-300">Lines: {lines.join(', ')}</span>
    </div>
  );
};

/**
 * Vulnerability Card - toggles between normal "CVE details" and "Protection Guide" 
 */
const VulnerabilityCard = ({ vuln }) => {
  const [isExpanded, setIsExpanded] = React.useState(false);
  const [isGuideView, setIsGuideView] = React.useState(false);

  // Normal CVE detail
  const rec = recommendations[vuln.type]; // "recommendation" object
  const matchedPattern = patterns[vuln.type] ? patterns[vuln.type].pattern.toString() : '';

  // Red/Blue Team data
  const guideData = vulnerabilityGuides[vuln.type] || {};

  // Severity styling
  const severityBadge = {
    CRITICAL: 'bg-red-500 text-white',
    HIGH: 'bg-orange-500 text-white',
    MEDIUM: 'bg-yellow-500 text-gray-800',
    LOW: 'bg-blue-500 text-white'
  }[vuln.severity] || 'bg-gray-500 text-white';

  // Toggle top-right button
  const handleGuideToggle = (e) => {
    e.stopPropagation();
    setIsGuideView(!isGuideView);
  };

  return (
    <div className="border border-gray-700 rounded-lg shadow-sm text-sm">
      {/* Header */}
      <div
        className="w-full flex items-center justify-between bg-gray-800 hover:bg-gray-700 transition-colors cursor-pointer p-4"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex-1 relative">
          {/* Toggle button */}
          <button 
            className="absolute -top-2 -right-2 py-1.5 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2 text-xs"
            onClick={handleGuideToggle}
          >
            <Shield className="w-4 h-4" />
            {isGuideView ? 'View CVE Details' : 'View Protection Guide'}
          </button>

          <span className={`text-xs font-semibold py-1 px-2 rounded-full uppercase ${severityBadge}`}>
            {vuln.severity}
          </span>
          <h3 className="text-lg font-medium mt-2">{vuln.description}</h3>
          <div className="text-xs text-gray-400 mt-1">
            Found in {vuln.files.length} file{vuln.files.length !== 1 ? 's' : ''}
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
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div className="p-4 bg-gray-700 text-gray-200">
          {!isGuideView ? (
            /* =============== CVE Details View =============== */
            <div>
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
                <div className="bg-gray-600 border border-gray-500 rounded-md p-3 text-xs leading-relaxed">
                  {rec.recommendation.split(/(Instead of:|Do:)/).map((section, index) => {
                    if (section === 'Instead of:' || section === 'Do:') {
                      return (
                        <div key={index} className="font-medium mt-3 mb-2 text-sm text-gray-100">
                          {section}
                        </div>
                      );
                    } else if (section.includes('```')) {
                      // Extract code blocks
                      const codeMatch = section.match(/```[\w]*\n([\s\S]*?)```/);
                      return codeMatch ? (
                        <pre
                          key={index}
                          className="bg-gray-800 text-gray-200 p-3 rounded-md my-2 overflow-x-auto text-xs"
                        >
                          <code>{codeMatch[1].trim()}</code>
                        </pre>
                      ) : null;
                    } else {
                      // Normal text
                      return (
                        <div
                          key={index}
                          className="prose prose-sm text-gray-100 max-w-none"
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
                      <h4 className="font-medium mb-2 text-sm text-gray-100">References</h4>
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
                      <h4 className="font-medium mb-2 text-sm text-gray-100">Detection Pattern</h4>
                      <pre className="bg-gray-800 p-2 text-xs text-gray-200 rounded overflow-auto">
                        {matchedPattern}
                      </pre>
                      {(vuln.category || vuln.subcategory) && (
                        <p className="text-xs text-gray-400 mt-2">
                          Category:{' '}
                          {Object.keys(patternCategories).find(
                            k => patternCategories[k] === vuln.category
                          )}{' '}
                          ({vuln.category})<br />
                          Subcategory: {vuln.subcategory}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div className="bg-gray-600 border border-gray-500 rounded-md p-3 text-sm">
                  No recommendation found for "{vuln.type}".
                </div>
              )}
            </div>
          ) : (
            /* =============== Protection Guide (Red/Blue) View =============== */
            <div className="text-xs space-y-6">
              {/* Main text content */}
              {guideData.title && (
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-600">
                  <h2 className="text-lg font-semibold text-blue-300 mb-3">{guideData.title}</h2>
                  <div
                    className="prose prose-invert text-gray-100 max-w-none"
                    dangerouslySetInnerHTML={{ __html: guideData.content || '' }}
                  />
                </div>
              )}

              {/* Red Team */}
              {guideData.redTeam && (
                <div className="bg-gray-800/50 rounded-lg p-4 border border-red-500/40">
                  <h3 className="text-md font-semibold text-red-400 mb-2">Red Team</h3>
                  <div
                    className="prose prose-invert text-gray-100 max-w-none"
                    dangerouslySetInnerHTML={{ __html: guideData.redTeam }}
                  />
                </div>
              )}

              {/* Blue Team - check if separate OS sections or single fallback */}
              {guideData.blueTeamWindows || guideData.blueTeamMac || guideData.blueTeamLinux ? (
                <div className="space-y-3">
                  {guideData.blueTeamWindows && (
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-blue-500/30">
                      <div
                        className="prose prose-invert text-gray-100 max-w-none"
                        dangerouslySetInnerHTML={{ __html: guideData.blueTeamWindows }}
                      />
                    </div>
                  )}
                  {guideData.blueTeamMac && (
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-blue-500/30">
                      <div
                        className="prose prose-invert text-gray-100 max-w-none"
                        dangerouslySetInnerHTML={{ __html: guideData.blueTeamMac }}
                      />
                    </div>
                  )}
                  {guideData.blueTeamLinux && (
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-blue-500/30">
                      <div
                        className="prose prose-invert text-gray-100 max-w-none"
                        dangerouslySetInnerHTML={{ __html: guideData.blueTeamLinux }}
                      />
                    </div>
                  )}
                </div>
              ) : guideData.blueTeam ? (
                <div className="bg-gray-800/50 rounded-lg p-4 border border-blue-500/40">
                  <h3 className="text-md font-semibold text-blue-400 mb-2">Blue Team</h3>
                  <div
                    className="prose prose-invert text-gray-100 max-w-none"
                    dangerouslySetInnerHTML={{ __html: guideData.blueTeam }}
                  />
                </div>
              ) : (
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-600">
                  <p className="text-gray-100">No Blue Team guidance found for this vulnerability.</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/**
 * Main Scan Results component
 */
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
  includeFirmware
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
        {/* Firmware/Binary Analysis Filter (disabled) */}
        <div className="flex items-center mb-6">
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={includeFirmware}
              onChange={() => {}}
              className="form-checkbox h-4 w-4 text-blue-600"
              disabled
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

        {/* View Toggle Buttons */}
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

        {/* Results */}
        {viewMode === 'type' ? (
          filteredByType.length ? (
            <div className="space-y-4">
              {filteredByType.map((vuln, idx) => (
                <VulnerabilityCard key={idx} vuln={vuln} />
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
                    <VulnerabilityCard key={idx} vuln={v} />
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

      {/* Floating nav for severity */}
      <FloatingNav
        activeSeverity={activeSeverity}
        setActiveSeverity={setActiveSeverity}
        severityStats={severityStats}
      />

      {/* Back to Top */}
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
    </div>
  );
};

export default ScanResults;
