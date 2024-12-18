import React from 'react';
import { Globe, Folder, Lock } from 'lucide-react';
import { Alert, AlertDescription } from './ui/alert';

const ScanButton = ({
  urlInput,
  setUrlInput,
  handleUrlScan,
  handleFileSelect,
  scanning,
  tokenValidated
}) => {
  const isPrivateRepo = urlInput.includes('/private/');
  const canScan = !scanning && (!isPrivateRepo || (isPrivateRepo && tokenValidated));

  return (
    <div className="space-y-6 mb-8">
      {/* URL Input */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 relative">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Enter repository URL (e.g., https://github.com/user/repo)"
            className="w-full px-5 py-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={scanning}
          />
          {isPrivateRepo && (
            <Lock className={`absolute right-3 top-3 h-5 w-5 ${tokenValidated ? 'text-green-500' : 'text-red-500'}`} />
          )}
        </div>
        <button
          onClick={handleUrlScan}
          disabled={!canScan || !urlInput}
          className={`flex items-center justify-center px-6 py-3 bg-blue-600 text-white rounded-lg shadow hover:bg-blue-700 transition-colors duration-300 ${
            (!canScan || !urlInput) ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          <Globe className="h-5 w-5 mr-2" />
          Scan Repository
        </button>
      </div>

      {/* File Input */}
      <div className="flex items-center justify-center">
        <label
          htmlFor="fileInput"
          className={`flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg shadow hover:bg-blue-700 transition-colors duration-300 cursor-pointer ${
            scanning ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          <Folder className="h-5 w-5 mr-2" />
          {scanning ? 'Scanning...' : 'Select Files'}
        </label>
        <input
          type="file"
          accept=".js,.ts,.jsx,.tsx,.json,.yml,.yaml"
          onChange={handleFileSelect}
          className="hidden"
          id="fileInput"
          multiple
          disabled={scanning}
        />
      </div>

      {/* Scanning Status */}
      {scanning && (
        <div className="text-center text-sm text-gray-600">
          Scanning in progress... Please wait.
        </div>
      )}
    </div>
  );
};

export default ScanButton;