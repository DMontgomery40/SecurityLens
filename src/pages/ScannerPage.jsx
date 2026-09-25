import React, { useEffect } from 'react';
import Home from '../components/Home.jsx';

// The original code scanner keeps its own dark interface.
export default function ScannerPage() {
  useEffect(() => {
    document.documentElement.classList.add('dark');
    return () => document.documentElement.classList.remove('dark');
  }, []);
  return (
    <div className="sl-legacy">
      <Home />
    </div>
  );
}
