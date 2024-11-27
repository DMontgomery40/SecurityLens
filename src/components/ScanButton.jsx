import React from 'react';
import { Globe, Folder } from 'lucide-react';

const ScanButton = ({
  urlInput,
  setUrlInput,
  handleUrlScan,
  handleFileSelect,
  scanning,
}) => {
  return (
    <div className="space-y-6 mb-8">
      {/* URL Input */}
      <div className="flex flex-col sm:flex-row gap-4">
        <input
          type="text"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="Enter repository URL (e.g., https://github.com/user/repo/tree/main/src)"
          className="flex-1 px-5 py-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={handleUrlScan}
          disabled={scanning || !urlInput}
          className={`flex items-center justify-center px-6 py-3 bg-blue-600 text-white rounded-lg shadow hover:bg-blue-700 transition-colors duration-300 ${
            scanning || !urlInput ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          <Globe className="h-5 w-5 mr-2" />
          Scan URL
        </button>
      </div>

      {/* File Input */}
      <div className="flex items-center justify-center">
        <label
          htmlFor="fileInput"
          className="flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg shadow hover:bg-blue-700 transition-colors duration-300 cursor-pointer"
        >
          <Folder className="h-5 w-5 mr-2" />
          Select Files
        </label>
        <input
          type="file"
          accept=".js,.ts,.jsx,.tsx"
          onChange={handleFileSelect}
          className="hidden"
          id="fileInput"
          multiple
        />
      </div>
    </div>
  );
};

export default ScanButton;