import React, { useEffect } from 'react';
import { FloatingNav } from './FloatingNav';
import { SeveritySummaryCard } from './SeveritySummaryCard';
import { useScanContext } from '../context/ScanContext';
import VulnerabilityCard from './VulnerabilityCard';


/**
 * Main Scan Results component
 */
const ScanResults = ({
  viewMode,
  setViewMode,
  searchQuery,
  setSearchQuery,
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
  // Get severity filter state from context
  const { activeSeverity, setActiveSeverity } = useScanContext();
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
                  vulnerability={vuln} 
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
                      vulnerability={v} 
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
