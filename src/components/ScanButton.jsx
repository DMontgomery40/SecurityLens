import React from 'react';

const ScanButton = ({ scanning, onClick, className }) => (
  <button
    onClick={onClick}
    disabled={scanning}
    className={`px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50 ${className}`}
  >
    {scanning ? 'Scanning...' : 'Start Scan'}
  </button>
);

export default ScanButton;