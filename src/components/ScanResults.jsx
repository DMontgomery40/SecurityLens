import React from 'react';
import { AlertTriangle, CheckCircle, Info, AlertCircle, RefreshCw } from 'lucide-react';

const ScanResults = ({ results, usedCache }) => {
  if (!results) return null;

  const { summary, findings, recommendedFixes } = results;

  const severityColors = {
    CRITICAL: 'bg-red-100 text-red-700',
    HIGH: 'bg-orange-100 text-orange-700',
    MEDIUM: 'bg-yellow-100 text-yellow-700',
    LOW: 'bg-blue-100 text-blue-700',
  };

  const severityIcons = {
    CRITICAL: AlertTriangle,
    HIGH: AlertCircle,
    MEDIUM: AlertCircle,
    LOW: Info,
  };

  return (
    <div className="space-y-6">
      {usedCache && (
        <div className="flex items-center justify-center p-2 bg-blue-50 text-blue-600 rounded-lg mb-4">
          <RefreshCw className="h-4 w-4 mr-2" />
          <span className="text-sm">Results from cached scan data</span>
        </div>
      )}

      {/* Summary Section */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-red-100 text-red-700 rounded-lg">
          <div className="text-2xl font-bold">{summary?.criticalIssues || 0}</div>
          <div className="text-sm font-medium">Critical</div>
        </div>
        <div className="p-4 bg-orange-100 text-orange-700 rounded-lg">
          <div className="text-2xl font-bold">{summary?.highIssues || 0}</div>
          <div className="text-sm font-medium">High</div>
        </div>
        <div className="p-4 bg-yellow-100 text-yellow-700 rounded-lg">
          <div className="text-2xl font-bold">{summary?.mediumIssues || 0}</div>
          <div className="text-sm font-medium">Medium</div>
        </div>
        <div className="p-4 bg-blue-100 text-blue-700 rounded-lg">
          <div className="text-2xl font-bold">{summary?.lowIssues || 0}</div>
          <div className="text-sm font-medium">Low</div>
        </div>
      </div>

      {/* Findings Section */}
      <div className="space-y-6">
        {Object.entries(findings || {}).map(([severity, issues]) => {
          if (!Array.isArray(issues) || issues.length === 0) return null;
          const Icon = severityIcons[severity];

          return (
            <div key={severity} className="space-y-4">
              <h3 className="text-lg font-semibold">{severity} Findings</h3>
              {issues.map((issue, index) => (
                <div
                  key={`${issue.type}-${index}`}
                  className={`p-4 rounded-lg ${severityColors[severity] || 'bg-gray-100 text-gray-700'}`}
                >
                  <div className="flex items-start">
                    {Icon && <Icon className="h-5 w-5 mr-2 mt-0.5" />}
                    <div>
                      <div className="font-medium">{issue.type}</div>
                      <div className="text-sm mt-1">{issue.description}</div>
                      <div className="text-sm mt-2">
                        <span className="font-medium">File:</span> {issue.file}
                      </div>
                      {Array.isArray(issue.lineNumbers) && issue.lineNumbers.length > 0 && (
                        <div className="text-sm">
                          <span className="font-medium">Line{issue.lineNumbers.length > 1 ? 's' : ''}:</span>{' '}
                          {issue.lineNumbers.join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Recommendations Section */}
      {Array.isArray(recommendedFixes) && recommendedFixes.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Recommendations</h3>
          <div className="space-y-3">
            {recommendedFixes.map((fix, index) => (
              <div
                key={index}
                className="p-4 bg-gray-100 text-gray-700 rounded-lg flex items-start"
              >
                <CheckCircle className="h-5 w-5 mr-2 mt-0.5 text-green-500" />
                <div>
                  <div className="font-medium">{fix.type}</div>
                  <div className="text-sm mt-1">{fix.recommendation}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cache Refresh Option */}
      {usedCache && summary?.totalIssues > 0 && (
        <div className="mt-8 flex justify-center">
          <button
            onClick={() => window.location.reload()}
            className="flex items-center px-4 py-2 text-sm text-blue-600 hover:text-blue-800"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Perform fresh scan
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanResults;