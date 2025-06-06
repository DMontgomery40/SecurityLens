import React, { useEffect } from 'react';
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
const VulnerabilityCard = ({ vuln, isExpanded, onToggleExpand, cardId }) => {
  const [isGuideView, setIsGuideView] = React.useState(false);

  // Mapping raw vulnerability type strings to the keys used in proactiveControlsData.
  const vulnerabilityGuideKeyMap = {
    'a09:2021 - security logging and monitoring failures': 'securityLogging',
    'insufficientlogging': 'securityLogging',
    'inadequatelogging': 'securityLogging',
    'securitylogging': 'securityLogging',
    'commandinjection': 'commandExecution',
    'commandexecution': 'commandExecution',
    'insecuresubmission': 'insecureSubmission',
    'insecuretransmission': 'insecureSubmission',
    'nosqlinjection': 'noSqlInjection',
    'hardcodedsecret': 'hardcodedSecret',
    'weakcrypto': 'weakCrypto',
    'insecurecryptousage': 'insecureCryptoUsage',
    'openredirect': 'openRedirect',
    'pathtraversal': 'pathTraversal',
  };
  const baseKey = vuln.type.toLowerCase().replace(/\s+/g, '');
  const normalizedType = vulnerabilityGuideKeyMap[baseKey] || vuln.type;
  const rec = recommendations[normalizedType] || recommendations[vuln.type];
  const matchedPattern = patterns[normalizedType] ? patterns[normalizedType].pattern.toString() : '';
  
  // Red/Blue Team data
  const guideData = vulnerabilityGuides[normalizedType] || {};

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
        onClick={() => onToggleExpand(cardId)}
      >
        <div>
          <div className="flex items-center space-x-2">
            <span className={`text-xs font-semibold py-1 px-2 rounded-full uppercase ${severityBadge}`}>
              {vuln.severity}
            </span>
            <span className="text-xs text-gray-400">
              Found in {vuln.files.length} file{vuln.files.length !== 1 ? 's' : ''}
            </span>
          </div>
          <h3 className="text-lg font-medium mt-1">{vuln.description}</h3>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={(e) => { e.stopPropagation(); handleGuideToggle(e); }}
            className="h-8 px-3 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors text-xs flex items-center gap-1 min-w-[120px] justify-center"
          >
            <Shield className="w-4 h-4" />
            {isGuideView ? "CVE Details" : "Protection Guide"}
          </button>
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
                <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
                  {/* Why it Matters */}
                  <div className="mb-4">
                    <h4 className="text-sm font-semibold text-blue-300 mb-2">Why it Matters</h4>
                    <p className="text-gray-300 text-sm">
                      Command injection can allow attackers to execute arbitrary system commands.
                    </p>
                  </div>

                  {/* What to Do */}
                  <div>
                    <h4 className="text-sm font-semibold text-blue-300 mb-2">What to Do</h4>
                    <div className="space-y-4 text-sm text-gray-300">
                      {rec.recommendation.split('<div class="example-block">').map((section, index) => {
                        if (section.includes('example-label')) {
                          // This is a code example section
                          const isVulnerable = section.includes('✕ Vulnerable:');
                          const label = isVulnerable ? '✕ Vulnerable:' : '✓ Safe:';
                          const code = section.split('<code>')[1]?.split('</code>')[0];
                          
                          return code ? (
                            <div key={index} className="mt-4">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`${isVulnerable ? 'text-red-400' : 'text-green-400'} text-sm`}>
                                  {label}
                                </span>
                              </div>
                              <pre className="bg-gray-950 p-3 text-gray-300 font-mono rounded border border-gray-800 overflow-x-auto whitespace-pre-wrap break-words">
                                <code>{code.trim()}</code>
                              </pre>
                            </div>
                          ) : null;
                        }

                        // Regular text and numbered items
                        return section.split('\n').map((line, lineIndex) => {
                          if (!line.trim()) return null;
                          
                          // If it's a numbered item
                          if (line.match(/^\d+\./)) {
                            return (
                              <div key={`${index}-${lineIndex}`} className="flex items-start">
                                <span className="mr-2">{line.match(/^\d+\./)[0]}</span>
                                <span>{line.replace(/^\d+\./, '').trim()}</span>
                              </div>
                            );
                          }
                          
                          // Regular text
                          return <p key={`${index}-${lineIndex}`}>{line.trim()}</p>;
                        });
                      })}
                    </div>
                  </div>

                  {/* Code Examples */}
                  {rec.examples && (
                    <div className="mt-4">
                      {rec.examples.map((example, index) => (
                        <div key={index} className="mt-4">
                          <div className="flex items-center gap-2 mb-1">
                            {example.type === 'vulnerable' ? (
                              <span className="text-red-400 text-sm">✕ Vulnerable:</span>
                            ) : (
                              <span className="text-green-400 text-sm">✓ Safe:</span>
                            )}
                          </div>
                          <pre className="bg-gray-950 p-3 text-sm text-gray-300 font-mono rounded border border-gray-800 overflow-x-auto whitespace-pre-wrap break-words">
                            <code>{example.code}</code>
                          </pre>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* References */}
                  {rec.references && rec.references.length > 0 && (
                    <div className="mt-6 pt-4 border-t border-gray-700">
                      <h4 className="text-sm font-semibold text-blue-300 mb-2">References</h4>
                      <ul className="space-y-1">
                        {rec.references.map((ref, i) => (
                          <li key={i}>
                            <a
                              href={ref.url}
                              className="text-sm text-blue-400 hover:text-blue-300 hover:underline inline-flex items-center gap-1"
                              target="_blank"
                              rel="noreferrer"
                            >
                              {ref.title}
                              <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                                <polyline points="15 3 21 3 21 9" />
                                <line x1="10" y1="14" x2="21" y2="3" />
                              </svg>
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Detection Pattern */}
                  {matchedPattern && (
                    <div className="mt-6 pt-4 border-t border-gray-700">
                      <h4 className="text-sm font-semibold text-blue-300 mb-2">Detection Pattern</h4>
                      <pre className="bg-gray-950 p-3 text-sm text-gray-300 font-mono rounded border border-gray-800 overflow-x-auto whitespace-pre-wrap break-words">
                        <code>{matchedPattern}</code>
                      </pre>
                      {(vuln.category || vuln.subcategory) && (
                        <div className="mt-2 text-sm text-gray-400">
                          <div>Category: {Object.keys(patternCategories).find(k => patternCategories[k] === vuln.category)} ({vuln.category})</div>
                          <div>Subcategory: {vuln.subcategory}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div className="bg-gray-900 rounded-lg p-4 border border-gray-700 text-gray-300">
                  No recommendation found for "{vuln.type}".
                </div>
              )}
            </div>
          ) : (
            /* =============== Protection Guide (Red/Blue) View =============== */
            <div className="space-y-6">
              {/* Try a Simulation (Coming Soon) */}
              <div className="border-2 border-dashed border-gray-600 rounded-lg p-4 text-center mb-4 bg-gray-800">
                <span className="text-blue-400 font-semibold">Try a Simulation</span>
                <span className="ml-2 text-sm text-yellow-400">(Coming Soon!)</span>
              </div>
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
  const [expandedCardId, setExpandedCardId] = React.useState(null);
  const resultsRef = React.useRef(null);

  // Scroll to results when they become available
  React.useEffect(() => {
    if (!scanning && (filteredByType.length > 0 || filteredByFile.length > 0)) {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanning, filteredByType.length, filteredByFile.length]);

  const handleCardToggle = (cardId) => {
    setExpandedCardId(expandedCardId === cardId ? null : cardId);
  };

  useEffect(() => {
    // Add a style tag to the document head for code block wrapping in .prose
    const style = document.createElement('style');
    style.innerHTML = `
      .prose pre, .prose code, .prose pre code {
        white-space: pre-wrap !important;
        word-break: break-word !important;
        overflow-x: auto !important;
        max-width: 100%;
        box-sizing: border-box;
      }
      #scanResults .prose p { margin:0.6rem 0; line-height:1.7; }
      #scanResults .prose { font-size:0.95rem; }
      #scanResults .prose li { margin-bottom:0.4rem; }
      #scanResults .prose a { color:#3b82f6; text-decoration:underline; }
      #scanResults .prose a:hover { color:#60a5fa; }
    `;
    document.head.appendChild(style);
    return () => { document.head.removeChild(style); };
  }, []);

  return (
    <div className="mt-8 relative" id="scanResults" ref={resultsRef}>
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
              className={`h-8 px-4 rounded text-sm min-w-[120px] ${
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
            className={`h-8 px-4 text-sm rounded min-w-[120px] ${
              viewMode === 'type' ? 'bg-gray-700 text-white font-medium' : 'bg-gray-800 text-gray-300'
            }`}
          >
            View by Vulnerability Type
          </button>
          <button
            onClick={() => setViewMode('file')}
            className={`h-8 px-4 text-sm rounded min-w-[120px] ${
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
                <VulnerabilityCard 
                  key={idx} 
                  vuln={vuln} 
                  cardId={`type-${idx}`}
                  isExpanded={expandedCardId === `type-${idx}`}
                  onToggleExpand={handleCardToggle}
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
            {filteredByFile.map(({ fileName, vulns }, fileIdx) => (
              <div key={fileName} className="border border-gray-700 rounded-lg p-4 bg-gray-800">
                <h3 className="text-lg font-semibold mb-3 text-gray-100">{fileName}</h3>
                <div className="space-y-4">
                  {vulns.map((v, vulnIdx) => (
                    <VulnerabilityCard 
                      key={vulnIdx} 
                      vuln={v} 
                      cardId={`file-${fileIdx}-${vulnIdx}`}
                      isExpanded={expandedCardId === `file-${fileIdx}-${vulnIdx}`}
                      onToggleExpand={handleCardToggle}
                    />
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
