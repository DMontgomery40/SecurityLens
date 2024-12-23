import React from 'react';
import { AlertTriangle, CheckCircle, Info, AlertCircle, RefreshCw, Clock } from 'lucide-react';
import { Alert, AlertDescription } from './ui/alert';

const SeverityBadge = ({ severity, count }) => {
  const colors = {
    CRITICAL: 'bg-red-100 text-red-800 border-red-200',
    HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
    MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    LOW: 'bg-blue-100 text-blue-800 border-blue-200'
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium border ${colors[severity] || 'bg-gray-100 text-gray-800 border-gray-200'}`}>
      {count}
    </span>
  );
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
    <div className="flex items-center text-sm text-gray-600">
      <Clock className="h-4 w-4 mr-1" />
      {timeLeft}
    </div>
  );
};

const ScanResults = ({ 
  results, 
  usedCache, 
  onRefreshRequest,
  scanning 
}) => {
  if (!results) return null;

  const { summary, findings, recommendedFixes, rateLimit } = results;

  // Add safety check for findings
  if (!findings || typeof findings !== 'object') {
    console.error('Invalid findings structure');
    return (
      <Alert variant="error">
        <AlertDescription>
          Invalid scan results structure. Please try again.
        </AlertDescription>
      </Alert>
    );
  }

  // Add safety check for recommendedFixes
  const safeRecommendedFixes = recommendedFixes && Array.isArray(recommendedFixes) 
    ? recommendedFixes 
    : [];

  // Helper function to get severity icon
  const getSeverityIcon = (severity) => {
    switch(severity) {
      case 'CRITICAL': return <AlertTriangle className="text-red-500" />;
      case 'HIGH': return <AlertCircle className="text-orange-500" />;
      case 'MEDIUM': return <AlertCircle className="text-yellow-500" />;
      case 'LOW': return <Info className="text-blue-500" />;
      default: return <Info />;
    }
  };

  // Helper function to consolidate findings by type
  const consolidateFindings = (findings) => {
    if (!findings || typeof findings !== 'object') {
        console.error('Invalid findings structure');
        return {};
    }
    
    const consolidated = {};
    
    try {
        Object.entries(findings).forEach(([category, subcategories]) => {
            if (!subcategories || typeof subcategories !== 'object') return;
            
            Object.entries(subcategories).forEach(([subcategory, issues]) => {
                if (!Array.isArray(issues)) return;
                
                issues.forEach(issue => {
                    if (!issue || !issue.type) return;
                    
                    const key = issue.type;
                    if (!consolidated[key]) {
                        consolidated[key] = {
                            ...issue,
                            files: [],
                            allLineNumbers: {}
                        };
                    }
                    consolidated[key].files.push(issue.file);
                    consolidated[key].allLineNumbers[issue.file] = issue.lineNumbers;
                });
            });
        });
    } catch (error) {
        console.error('Error consolidating findings:', error);
    }
    
    return consolidated;
  };

  return (
    <div className="space-y-6">
      {/* Rate Limit Info */}
      {rateLimit && (
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg mb-4">
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
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => (
          <div key={severity} className={`p-4 rounded-lg ${
            severity === 'CRITICAL' ? 'bg-red-100' :
            severity === 'HIGH' ? 'bg-orange-100' :
            severity === 'MEDIUM' ? 'bg-yellow-100' : 'bg-blue-100'
          }`}>
            <div className="text-2xl font-bold">
              {summary[`${severity.toLowerCase()}Issues`] || 0}
            </div>
            <div className="text-sm font-medium">{severity}</div>
          </div>
        ))}
      </div>

      {/* Consolidated Findings */}
      <div className="space-y-8">
        {Object.entries(consolidateFindings(findings)).map(([type, finding]) => (
          <div key={type} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-start">
              {getSeverityIcon(finding.severity)}
              <div className="ml-3 flex-1">
                <h3 className="text-lg font-medium">
                  {type}
                  {finding.subcategory && (
                    <span className="text-sm text-gray-500 ml-2">
                      CWE-{finding.subcategory}
                    </span>
                  )}
                </h3>
                <p className="text-gray-600 mt-1">{finding.description}</p>
                
                {/* Affected Files */}
                <div className="mt-4 space-y-2">
                  {Object.entries(finding.allLineNumbers).map(([file, lines]) => (
                    <div key={file} className="text-sm">
                      <code className="bg-gray-100 px-2 py-1 rounded">
                        {file}
                      </code>
                      {lines?.length > 0 && (
                        <span className="ml-2 text-gray-600">
                          Line{lines.length > 1 ? 's' : ''}: {lines.join(', ')}
                        </span>
                      )}
                    </div>
                  ))}
                </div>

                {/* Recommendation */}
                {finding.recommendation && (
                  <Alert className="mt-4" variant="info">
                    <AlertDescription>
                      {finding.recommendation}
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* References Section */}
      {safeRecommendedFixes.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">
            Security References & Mitigation
          </h2>
          <div className="space-y-4">
            {Array.from(new Set(safeRecommendedFixes.map(fix => fix.type))).map(type => {
              const fix = safeRecommendedFixes.find(f => f.type === type);
              return (
                <div key={type} className="border-t pt-4 first:border-t-0 first:pt-0">
                  <h3 className="font-medium">
                    {type}
                    {fix.cwe && (
                      <a 
                        href={`https://cwe.mitre.org/data/definitions/${fix.cwe}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-2 text-sm text-blue-600 hover:text-blue-800"
                      >
                        (CWE-{fix.cwe})
                      </a>
                    )}
                  </h3>
                  <p className="text-gray-600 mt-1">{fix.recommendation}</p>
                  {fix.references?.length > 0 && (
                    <div className="mt-2">
                      <div className="text-sm font-medium">Additional Resources:</div>
                      <ul className="list-disc pl-5 text-sm text-gray-600">
                        {fix.references.map((ref, i) => (
                          <li key={i}>
                            <a 
                              href={ref.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-600 hover:text-blue-800"
                            >
                              {ref.title}
                            </a>
                            {ref.description && (
                              <span className="text-gray-500"> - {ref.description}</span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Cache Notice */}
      {usedCache && (
        <Alert className="mt-4">
          <AlertDescription className="flex items-center">
            <Info className="h-4 w-4 mr-2" />
            Results are from cached data. 
            {!scanning && (
              <button
                onClick={onRefreshRequest}
                className="ml-2 text-blue-600 hover:text-blue-800"
                disabled={rateLimit?.remaining === 0}
              >
                Perform fresh scan
              </button>
            )}
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};

export default ScanResults;