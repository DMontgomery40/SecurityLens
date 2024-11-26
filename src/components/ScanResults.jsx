import React from 'react';
import { Shield, File } from 'lucide-react';

const SeverityCard = ({ title, count, bgColor }) => (
  <div className={`p-4 ${bgColor} rounded`}>
    <div className="font-bold">{title}</div>
    <div className="text-2xl">{count}</div>
  </div>
);

const Finding = ({ finding }) => (
  <div className="bg-gray-50 p-4 rounded">
    <div className="flex items-start">
      <Shield className="h-5 w-5 mt-1 mr-2" />
      <div>
        <h3 className="font-bold">{finding.type}</h3>
        <p className="text-gray-600">{finding.description}</p>
        <div className="mt-2 flex items-center">
          <File className="h-4 w-4 mr-2" />
          <span className="text-sm">
            {finding.file} (lines: {finding.lineNumbers.join(', ')})
          </span>
        </div>
      </div>
    </div>
  </div>
);

const ScanResults = ({ results }) => {
  if (!results) return null;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-4 gap-4">
        <SeverityCard
          title="Critical"
          count={results.summary.criticalIssues}
          bgColor="bg-red-100"
        />
        <SeverityCard
          title="High"
          count={results.summary.highIssues}
          bgColor="bg-orange-100"
        />
        <SeverityCard
          title="Medium"
          count={results.summary.mediumIssues}
          bgColor="bg-yellow-100"
        />
        <SeverityCard
          title="Low"
          count={results.summary.lowIssues}
          bgColor="bg-blue-100"
        />
      </div>

      <div className="space-y-4">
        {Object.entries(results.findings).map(([severity, findings]) => (
          <div key={severity} className="border rounded p-4">
            <h2 className={`text-xl font-bold mb-4`}>
              {severity} Findings
            </h2>
            <div className="space-y-4">
              {findings.map((finding, index) => (
                <Finding key={index} finding={finding} />
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="border rounded p-4">
        <h2 className="text-xl font-bold mb-4">Recommendations</h2>
        <div className="space-y-4">
          {results.recommendedFixes.map((fix, index) => (
            <div key={index} className="bg-gray-50 p-4 rounded">
              <div className="font-bold">{fix.type}</div>
              <div className="text-gray-600">{fix.recommendation}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ScanResults;