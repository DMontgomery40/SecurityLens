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

  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const severityIcons = {
    CRITICAL: AlertTriangle,
    HIGH: AlertCircle,
    MEDIUM: AlertCircle,
    LOW: Info
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
        {severityOrder.map(severity => (
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

      {/* Findings Sections */}
      <div className="space-y-6">
        {severityOrder.map(severity => {
          const issuesList = findings[severity] || [];
          if (issuesList.length === 0) return null;

          const Icon = severityIcons[severity];
          
          return (
            <div key={severity} className="space-y-4">
              <h3 className="text-lg font-semibold flex items-center">
                {Icon && <Icon className="h-5 w-5 mr-2" />}
                {severity} Findings
                <SeverityBadge severity={severity} count={issuesList.length} />
              </h3>
              
              {issuesList.map((issue, index) => (
                <div key={`${issue.type}-${index}`} className="p-4 rounded-lg bg-white border">
                  <div className="space-y-2">
                    <div className="font-medium text-gray-900">{issue.type}</div>
                    <div className="text-sm text-gray-600">{issue.description}</div>
                    <div className="text-sm">
                      <span className="font-medium">File: </span>
                      <code className="px-2 py-1 bg-gray-100 rounded">{issue.file}</code>
                    </div>
                    {Array.isArray(issue.lineNumbers) && issue.lineNumbers.length > 0 && (
                      <div className="text-sm">
                        <span className="font-medium">Line{issue.lineNumbers.length > 1 ? 's' : ''}: </span>
                        <code className="px-2 py-1 bg-gray-100 rounded">
                          {issue.lineNumbers.join(', ')}
                        </code>
                      </div>
                    )}
                    {issue.recommendation && (
                      <Alert className="mt-2">
                        <AlertDescription>{issue.recommendation}</AlertDescription>
                      </Alert>
                    )}
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Recommended Fixes Section */}
      {recommendedFixes && recommendedFixes.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold flex items-center">
            <CheckCircle className="h-5 w-5 mr-2" />
            Recommended Security Fixes
          </h3>
          {recommendedFixes.map((fix, index) => (
            <div key={index} className="p-4 rounded-lg bg-white border">
              <div className="space-y-3">
                <div className="font-medium text-gray-900 flex items-center">
                  <AlertTriangle className="h-4 w-4 mr-2 text-orange-500" />
                  {fix.type}
                </div>
                <div className="text-sm space-y-2">
                  <div className="font-medium">Mitigation Steps:</div>
                  <div className="text-gray-700">{fix.recommendation?.toString()}</div>
                  {fix.references && fix.references.length > 0 && (
                    <div className="mt-2">
                      <div className="font-medium text-sm">Security References:</div>
                      <ul className="list-disc pl-4 text-sm text-gray-600 space-y-1">
                        {fix.references?.map((ref, i) => (
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
                  {fix.cwe && (
                    <div className="mt-2">
                      <div className="font-medium text-sm">CWE Reference:</div>
                      <a 
                        href={`https://cwe.mitre.org/data/definitions/${fix.cwe}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-blue-600 hover:text-blue-800"
                      >
                        CWE-{fix.cwe?.toString()}
                      </a>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
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