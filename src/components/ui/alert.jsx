import React from 'react';

export function Alert({ children, className = '', variant = 'default' }) {
  const variants = {
    default: 'bg-gray-100 border-gray-200',
    warning: 'bg-yellow-100 border-yellow-200',
    error: 'bg-red-100 border-red-200',
    info: 'bg-blue-100 border-blue-200'
  };

  return (
    <div className={`p-4 rounded-lg border ${variants[variant]} ${className}`}>
      {children}
    </div>
  );
}

export function AlertDescription({ children }) {
  return <div className="text-sm">{children}</div>;
}