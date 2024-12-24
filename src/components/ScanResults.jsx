import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  Shield, 
  Info, 
  AlertCircle, 
  RefreshCw, 
  Clock,
  ExternalLink,
  Book
} from 'lucide-react';

const severityConfig = {
  CRITICAL: {
    icon: AlertTriangle,
    color: 'text-red-600',
    bg: 'bg-red-50',
    border: 'border-red-100',
    badge: 'danger',
    lightBg: 'bg-red-50/50',
    hoverBg: 'hover:bg-red-100/50'
  },
  HIGH: {
    icon: AlertCircle,
    color: 'text-orange-600',
    bg: 'bg-orange-50',
    border: 'border-orange-100',
    badge: 'warning',
    lightBg: 'bg-orange-50/50',
    hoverBg: 'hover:bg-orange-100/50'
  },
  MEDIUM: {
    icon: AlertCircle,
    color: 'text-yellow-600',
    bg: 'bg-yellow-50',
    border: 'border-yellow-100',
    badge: 'warning',
    lightBg: 'bg-yellow-50/50',
    hoverBg: 'hover:bg-yellow-100/50'
  },
  LOW: {
    icon: Info,
    color: 'text-blue-600',
    bg: 'bg-blue-50',
    border: 'border-blue-100',
    badge: 'info',
    lightBg: 'bg-blue-50/50',
    hoverBg: 'hover:bg-blue-100/50'
  }
};

const TimeToReset = ({ resetTimestamp }) => {
  const [timeLeft, setTimeLeft] = React.useState('');

  React.useEffect(() => {
    const updateTime = () => {
      const now = new Date().getTime();
      const reset = new Date(resetTimestamp * 1000).getTime();
      const diff = reset - now;

      if (diff <= 0) {
        setTimeLeft('Reset now');
        return;
      }

      const minutes = Math.floor(diff / 60000);
      const seconds = Math.floor((diff % 60000) / 1000);
      setTimeLeft(`${minutes}m ${seconds}s`);
    };

    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, [resetTimestamp]);

  return (
    <div className="flex items-center text-sm font-medium text-gray-500">
      <Clock className="h-4 w-4 mr-1.5 text-gray-400" />
      {timeLeft}
    </div>
  );
};

const SeverityCard = ({ severity, count, isSelected, onClick }) => {
  const config = severityConfig[severity];
  const Icon = config.icon;
  
  return (
    <button
      onClick={onClick}
      className={`
        relative w-full rounded-xl p-6 transition-all duration-200
        ${isSelected ? `${config.bg} ring-2 ring-${severity.toLowerCase()}-500 ring-opacity-50` : 'bg-white hover:bg-gray-50'}
        group
      `}
    >
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <div className="text-3xl font-bold">{count}</div>
          <div className="text-sm font-medium flex items-center space-x-2">
            <Icon className={`h-4 w-4 ${config.color}`} />
            <span>{severity}</span>
          </div>
        </div>
        {count > 0 && (
          <div className={`
            opacity-0 group-hover:opacity-100 transition-opacity
            text-sm font-medium ${config.color}
          `}>
            {isSelected ? 'Clear Filter' : 'Show Only'}
          </div>
        )}
      </div>
    </button>
  );
};

const FindingCard = ({ finding, type }) => {
  const config = severityConfig[finding.severity] || severityConfig.LOW; // Fallback to LOW if severity not found
  const Icon = config.icon;

  return (
    <div className={`rounded-lg overflow-hidden ${config.lightBg || ''} ${config.hoverBg || ''} transition-colors duration-200`}>
      <div className="p-6">
        <div className="flex items-start space-x-4">
          <div className="bg-white/50 p-2 rounded-lg">
            <Icon className={`h-5 w-5 ${config.color}`} />
          </div>
          <div className="flex-1 min-w-0 space-y-4">
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-lg font-semibold text-gray-900">
                  {type}
                </h3>
                {finding.subcategory && (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100">
                    CWE-{finding.subcategory}
                  </span>
                )}
              </div>
              <p className="mt-1 text-gray-600">
                {finding.description}
              </p>
            </div>

            {/* Affected Files */}
            {Object.entries(finding.allLineNumbers).length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center space-x-2 text-sm text-gray-500">
                  <Info className="h-4 w-4" />
                  <span>Affected Files</span>
                </div>
                <div className="space-y-2">
                  {Object.entries(finding.allLineNumbers).map(([file, lines]) => (
                    <div key={file} className="rounded-md bg-white/50 p-3 font-mono text-sm">
                      <div className="flex items-start justify-between">
                        <div className="font-medium text-gray-900">
                          {file}
                        </div>
                        {lines?.length > 0 && (
                          <div className="text-gray-500 ml-4">
                            Line{lines.length > 1 ? 's' : ''}: {lines.join(', ')}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {finding.recommendation && (
              <div className="bg-white/80 rounded-lg p-4 text-gray-800">
                <div className="flex space-x-2">
                  <Info className="h-4 w-4 mt-1 flex-shrink-0" />
                  <p>{finding.recommendation}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const ReferencesSection = ({ fixes, findings }) => {
  const [expandedSection, setExpandedSection] = useState(null);

  // Consolidate fixes and associate with affected files
  const consolidatedFixes = React.useMemo(() => {
    const fixMap = new Map();
    
    fixes.forEach(fix => {
      if (!fixMap.has(fix.type)) {
        fixMap.set(fix.type, {
          ...fix,
          affectedFiles: new Set()
        });
      }
    });

    // Associate files with each fix type
    Object.entries(findings || {}).forEach(([type, finding]) => {
      const fix = fixes.find(f => f.type === type);
      if (fix && finding.files) {
        const consolidated = fixMap.get(fix.type);
        finding.files.forEach(file => consolidated.affectedFiles.add(file));
      }
    });

    return Array.from(fixMap.values());
  }, [fixes, findings]);

  const toggleSection = (type) => {
    setExpandedSection(expandedSection === type ? null : type);
  };

  return (
    <div className="space-y-6">
      {consolidatedFixes.map((fix) => {
        const isExpanded = expandedSection === fix.type;
        const fileCount = fix.affectedFiles.size;
        
        return (
          <div key={fix.type} className="overflow-hidden transition-all duration-200">
            <button
              onClick={() => toggleSection(fix.type)}
              className="w-full text-left p-6 bg-white rounded-lg shadow-sm hover:bg-gray-50 transition-colors duration-200"
            >
              <div className="flex items-center justify-between">
                <div className="space-y-1 flex-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-semibold text-gray-900">{fix.type}</h3>
                      {fix.cwe && (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          CWE-{fix.cwe}
                        </span>
                      )}
                      {fileCount > 0 && (
                        <span className="text-sm text-gray-500">
                          {fileCount} affected {fileCount === 1 ? 'file' : 'files'}
                        </span>
                      )}
                    </div>
                  </div>
                  <p className="text-gray-600 pr-8">{fix.recommendation}</p>
                </div>
                <div className={`transform transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                  <svg className="w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* Show affected files in a compact way when collapsed */}
              {!isExpanded && fileCount > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {Array.from(fix.affectedFiles).slice(0, 3).map(file => (
                    <span key={file} className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-600">
                      {file.split('/').pop()}
                    </span>
                  ))}
                  {fileCount > 3 && (
                    <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-600">
                      +{fileCount - 3} more
                    </span>
                  )}
                </div>
              )}
            </button>

            {isExpanded && (
              <div className="mt-2 space-y-4">
                {/* Show full file list when expanded */}
                {fileCount > 0 && (
                  <div className="px-6 py-3 bg-gray-50 rounded-lg">
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Affected Files:</h4>
                    <div className="space-y-1">
                      {Array.from(fix.affectedFiles).map(file => (
                        <div key={file} className="text-sm text-gray-600 font-mono">
                          {file}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* References */}
                {fix.references?.length > 0 && (
                  <div className="space-y-2 px-2">
                    {fix.references.map((ref, i) => (
                      <a
                        key={i}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors duration-200"
                      >
                        <div className="flex items-start space-x-3">
                          <Book className="h-5 w-5 text-blue-500 mt-0.5" />
                          <div className="flex-1">
                            <div className="font-medium text-blue-600 flex items-center">
                              {ref.title}
                              <ExternalLink className="h-3 w-3 ml-1" />
                            </div>
                            {ref.description && (
                              <p className="mt-1 text-sm text-gray-600">{ref.description}</p>
                            )}
                          </div>
                        </div>
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  const [selectedSeverity, setSelectedSeverity] = useState(null);

  if (!results) return null;

  const { summary, findings, recommendedFixes, rateLimit } = results;

  return (
    <div className="space-y-6">
      {/* Rate Limit Info */}
      {rateLimit && (
        <div className="flex items-center justify-between p-4 bg-white rounded-lg">
          <div className="flex items-center space-x-4">
            <div className="text-sm text-gray-600">
              API Calls Remaining: {rateLimit.remaining}/{rateLimit.limit}
            </div>
            <TimeToReset resetTimestamp={rateLimit.reset} />
          </div>
          {usedCache && !scanning && (
            <button
              onClick={onRefreshRequest}
              className="flex items-center text-sm text-blue-600 hover:text-blue-800"
              disabled={rateLimit.remaining === 0}
            >
              <RefreshCw className="h-4 w-4 mr-1" />
              Refresh Scan
            </button>
          )}
        </div>
      )}

      {/* Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {Object.entries(severityConfig).map(([severity]) => (
          <SeverityCard
            key={severity}
            severity={severity}
            count={summary[`${severity.toLowerCase()}Issues`] || 0}
            isSelected={selectedSeverity === severity}
            onClick={() => setSelectedSeverity(selectedSeverity === severity ? null : severity)}
          />
        ))}
      </div>

      {/* Findings */}
      <div className="space-y-4">
        {Object.entries(findings).map(([type, finding]) => {
          if (selectedSeverity && finding.severity !== selectedSeverity) {
            return null;
          }
          return <FindingCard key={type} finding={finding} type={type} />;
        })}
      </div>

      {/* References Section */}
      {recommendedFixes?.length > 0 && (
        <div className="bg-white rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">
            Security References & Mitigation
          </h2>
          <ReferencesSection fixes={recommendedFixes} findings={findings} />
        </div>
      )}

      {/* Cache Notice */}
      {usedCache && (
        <div className="flex items-center justify-between p-4 bg-blue-50 text-blue-700 rounded-lg">
          <div className="flex items-center">
            <Info className="h-5 w-5 mr-2" />
            Results are from cached data
          </div>
          {!scanning && (
            <button
              onClick={onRefreshRequest}
              className="text-blue-600 hover:text-blue-800"
              disabled={rateLimit?.remaining === 0}
            >
              Perform fresh scan
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default ScanResults;
