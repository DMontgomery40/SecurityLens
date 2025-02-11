import React from 'react';

export const SeveritySummaryCard = ({ severity, count, totalInstances, isActive, onClick }) => {
  const severityStyles = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-blue-500'
  };

  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-lg border-2 transition-transform transform hover:scale-105 ${
        isActive ? 'border-gray-300 shadow-lg' : 'border-transparent shadow'
      } ${severityStyles[severity]} text-white`}
    >
      <div className="text-sm font-semibold mb-1">
        {severity.charAt(0) + severity.slice(1).toLowerCase()}
      </div>
      <div className="text-3xl font-bold">{count}</div>
      <div className="text-sm">Unique Vulnerabilities</div>
      <div className="text-sm mt-1">{totalInstances} Total Instances</div>
    </button>
  );
};
