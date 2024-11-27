import React from 'react';
import { AlertTriangle, CheckCircle, Info, AlertCircle } from 'lucide-react';

const ScanResults = ({ results }) => {
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
      {/* Summary Section */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-red-100 text-red-700 rounded-lg">
          <div className="text-2xl font-bold">{summary.criticalIssues}</div>
          <div className="text-sm font-medium">Critical</div>
        </div>
        <div className="p-4 bg-orange-100 text-orange-700 rounded-lg">
          <div className="text-2xl font-bold">{summary.highIssues}</div>
          <div className="text-sm font-medium">High</div>
        </div>
        <div className="p-4 bg-yellow-100 text-yellow-700 rounded-lg">
          <div className="text-2xl font-bold">{summary.mediumIssues}</div>
          <div className="text-sm font-medium">Medium</div>
        </div>
        <div className="p-4 bg-blue-100 text-blue-700 rounded-lg">
          <div className="text-2xl font-bold">{summary.lowIssues}</div>
          <div className="text-sm font-medium">Low</div>
        </div>
      </div>

      {/* Findings Section */}
      <div className="space-y-6">
        {Object.entries(findings).map(([severity, issues]) => {
          if (issues.length === 0) return null;
          const Icon = severityIcons[severity];

          return (
            <div key={severity} className="space-y-4">
              <h3 className="text-lg font-semibold">{severity} Findings</h3>
              {issues.map((issue, index) => (
                <div
                  key={`${issue.type}-${index}`}
                  className={`p-4 rounded-lg ${severityColors[severity]}`}
                >
                  <div className="flex items-start">
                    <Icon className="h-5 w-5 mr-2 mt-0.5" />
                    <div>
                      <div className="font-medium">{issue.type}</div>
                      <div className="text-sm mt-1">{issue.description}</div>
                      <div className="text-sm mt-2">
                        <span className="font-medium">File:</span> {issue.file}
                      </div>
                      {issue.lineNumbers && issue.lineNumbers.length > 0 && (
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
      {recommendedFixes && recommendedFixes.length > 0 && (
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
    </div>
  );
};

export default ScanResults;
