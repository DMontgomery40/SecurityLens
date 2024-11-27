// src/components/ui/ScanResults.jsx

import React from 'react';
import { Shield, File } from 'lucide-react';

const SeverityCard = ({ title, count, bgColor, icon }) => (
  <div className={`p-6 ${bgColor} rounded-lg shadow-md flex items-center`}>
    <div className="p-3 bg-white rounded-full shadow-sm mr-4">
      {icon}
    </div>
    <div>
      <h4 className="text-sm font-semibold text-gray-700">{title}</h4>
      <p className="text-xl font-bold text-gray-900">{count}</p>
    </div>
  </div>
);

const Finding = ({ finding }) => (
  <div className="bg-white p-5 rounded-lg shadow hover:shadow-lg transition-shadow duration-300">
    <div className="flex items-start">
      <Shield className="h-6 w-6 text-red-500 mr-3 mt-1" />
      <div>
        <h3 className="text-lg font-semibold text-gray-800">{finding.type}</h3>
        <p className="text-gray-600 mt-1">{finding.description}</p>
        <div className="mt-3 flex items-center text-sm text-gray-500">
          <File className="h-4 w-4 mr-2" />
          <span>
            {finding.file} <span className="font-medium">({finding.lineNumbers.join(', ')})</span>
          </span>
        </div>
      </div>
    </div>
  </div>
);

const ScanResults = ({ results }) => {
  if (!results) return null;

  return (
    <div className="space-y-8">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <SeverityCard
          title="Critical"
          count={results.summary.criticalIssues}
          bgColor="bg-red-100"
          icon={<Shield className="h-6 w-6 text-red-600" />}
        />
        <SeverityCard
          title="High"
          count={results.summary.highIssues}
          bgColor="bg-orange-100"
          icon={<Shield className="h-6 w-6 text-orange-600" />}
        />
        <SeverityCard
          title="Medium"
          count={results.summary.mediumIssues}
          bgColor="bg-yellow-100"
          icon={<Shield className="h-6 w-6 text-yellow-600" />}
        />
        <SeverityCard
          title="Low"
          count={results.summary.lowIssues}
          bgColor="bg-blue-100"
          icon={<Shield className="h-6 w-6 text-blue-600" />}
        />
      </div>

      {/* Findings Section */}
      <div className="space-y-6">
        {Object.entries(results.findings).map(([severity, findings]) => (
          <div key={severity} className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-bold mb-5 text-gray-800">
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

      {/* Recommendations Section */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-5 text-gray-800">Recommendations</h2>
        <div className="space-y-4">
          {results.recommendedFixes.map((fix, index) => (
            <div key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
              <div className="text-lg font-semibold text-gray-700">{fix.type}</div>
              <div className="text-gray-600 mt-2">{fix.recommendation}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ScanResults;
