import React from 'react';

export function AlertDialog({ children, open, onClose }) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-md w-full">
        <div className="p-6">
          {children}
        </div>
        <div className="border-t px-6 py-4">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded text-sm"
          >
            Close
          </button>
        </div>
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