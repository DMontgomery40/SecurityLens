import React from 'react';

export function AlertDialog({ children, open, onClose }) {
  if (!open) return null;

  // Outer backdrop (fills screen, dark overlay).
  // Notice onClick={onClose} so clicking outside the white box closes the dialog.
  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={onClose}
    >
      {/* Inner container (the white box). 
          We stopPropagation so clicks on the white box don't close. */}
      <div
        className="relative bg-white rounded-lg w-full max-w-3xl max-h-[80vh] overflow-auto p-4"
        onClick={e => e.stopPropagation()}
      >
        {/* "Close" button up top-right */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
        >
          ✕
        </button>

        {children}
      </div>
    </div>
  );
}

export function AlertDialogContent({ children }) {
  return <div className="space-y-4">{children}</div>;
}

export function AlertDialogHeader({ children }) {
  return <div className="mb-4">{children}</div>;
}
