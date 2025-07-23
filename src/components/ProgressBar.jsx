import React from 'react';

const ProgressBar = ({ progress, onCancel, scanning }) => {
  if (!scanning) return null;

  return (
    <div className="my-6">
      <div className="w-full bg-gray-600 rounded-full h-3 overflow-hidden">
        <div
          className="bg-blue-400 h-3 rounded-full transition-all duration-300"
          style={{ width: `${progress.total ? (progress.current / progress.total) * 100 : 0}%` }}
        />
      </div>
      <div className="text-sm text-gray-300 mt-2 text-center">
        {progress.phase === 'fetching' && progress.total > 0 && progress.details?.successCount !== undefined
          ? `Fetching files (${progress.current}/${progress.total}) • ✓${progress.details.successCount} ✗${progress.details.failureCount}`
          : progress.phase === 'fetching' && progress.total > 0
          ? `Fetching files (${progress.current} of ${progress.total})`
          : progress.phase === 'analyzing' && progress.total > 0 && progress.details?.successCount !== undefined
          ? `Analyzing files (${progress.current}/${progress.total}) • ✓${progress.details.successCount} ✗${progress.details.failureCount}`
          : progress.phase === 'completed' && progress.details?.summary
          ? progress.details.summary
          : progress.phase === 'analyzing' && progress.details?.currentFile
          ? `Analyzing: ${progress.details.currentFile} (${progress.current} of ${progress.total})`
          : progress.phase === 'complete'
          ? 'Scan complete!'
          : `${progress.phase}: ${progress.current} of ${progress.total}`}
      </div>
      {progress.phase === 'completed' && progress.details?.failureCount > 0 && (
        <div className="text-xs text-yellow-400 mt-1 text-center">
          ⚠️ {progress.details.failureCount} files couldn't be downloaded - scan may be incomplete
        </div>
      )}
      {onCancel && (
        <div className="text-center mt-2">
          <button
            onClick={onCancel}
            className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-500 text-sm"
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
};

export default ProgressBar;