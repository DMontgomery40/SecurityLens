import React from 'react';
import { useScanContext } from '../context/ScanContext';

const FilterPanel = () => {
  const {
    searchQuery,
    setSearchQuery,
    viewMode,
    setViewMode,
    scanResults
  } = useScanContext();

  if (!scanResults) return null;

  return (
    <div className="mb-6 space-y-4">
      {/* Search Box */}
      <div>
        <input
          type="text"
          placeholder="Search vulnerabilities..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg 
                    focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      {/* View Mode Toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setViewMode('type')}
          className={`px-4 py-2 rounded-lg text-sm transition-colors ${
            viewMode === 'type'
              ? 'bg-blue-500 text-white'
              : 'bg-gray-600 text-gray-200 hover:bg-gray-500'
          }`}
        >
          By Type
        </button>
        <button
          onClick={() => setViewMode('file')}
          className={`px-4 py-2 rounded-lg text-sm transition-colors ${
            viewMode === 'file'
              ? 'bg-blue-500 text-white'
              : 'bg-gray-600 text-gray-200 hover:bg-gray-500'
          }`}
        >
          By File
        </button>
      </div>
    </div>
  );
};

export default FilterPanel;