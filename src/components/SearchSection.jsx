import React from 'react';

const SearchSection = ({ urlInput, setUrlInput, handleWebsiteScan, scanning }) => {
  return (
    <div className="mb-8">
      <div className="flex gap-4 mb-4">
        <input
          type="text"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="Enter URL or GitHub repository"
          className="flex-1 px-4 py-2 bg-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={() => handleWebsiteScan(urlInput)}
          disabled={scanning}
          className={`px-6 py-2 ${
            scanning 
              ? 'bg-gray-600 cursor-not-allowed' 
              : 'bg-blue-600 hover:bg-blue-700'
          } text-white rounded-lg transition-colors`}
        >
          {scanning ? 'Scanning...' : 'Scan'}
        </button>
      </div>
    </div>
  );
};

export default SearchSection; 