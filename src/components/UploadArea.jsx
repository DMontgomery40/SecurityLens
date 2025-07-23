import React from 'react';

const UploadArea = ({ onFileSelected, shouldShow = true }) => {
  if (!shouldShow) return null;

  return (
    <div className="border-2 border-dashed border-gray-600 rounded-lg p-4 text-center">
      <input
        type="file"
        id="fileInput"
        multiple
        onChange={onFileSelected}
        className="hidden"
      />
      <label
        htmlFor="fileInput"
        className="block cursor-pointer"
      >
        <p className="text-gray-300">Drag and drop files here, or click to select files</p>
        <p className="text-sm text-gray-500 mt-1">Supported files: .js, .jsx, .ts, .tsx, .py, etc.</p>
      </label>
    </div>
  );
};

export default UploadArea;