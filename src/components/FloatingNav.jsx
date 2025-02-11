import React from 'react';

export const FloatingNav = ({ activeSeverity, setActiveSeverity, severityStats }) => (
  <div className="fixed right-4 top-1/2 transform -translate-y-1/2 bg-gray-800 rounded-lg shadow-lg border border-gray-700 p-2 hidden lg:block">
    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
      <button
        key={sev}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setActiveSeverity(activeSeverity === sev ? 'ALL' : sev);
        }}
        className={`flex items-center gap-2 px-3 py-2 rounded-md w-full mb-1 last:mb-0 transition-colors ${
          activeSeverity === sev ? 'bg-gray-700' : 'hover:bg-gray-600'
        }`}
      >
        <div
          className={`w-2 h-2 rounded-full ${
            sev === 'CRITICAL'
              ? 'bg-red-500'
              : sev === 'HIGH'
              ? 'bg-orange-500'
              : sev === 'MEDIUM'
              ? 'bg-yellow-500'
              : sev === 'LOW'
              ? 'bg-blue-500'
              : 'bg-gray-500'
          }`}
        />
        <span className="text-sm">{severityStats[sev].uniqueCount}</span>
      </button>
    ))}
  </div>
);
