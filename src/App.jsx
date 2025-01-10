import React, { useEffect } from 'react';
import ScannerUI from './components/ScannerUI';

function App() {
  useEffect(() => {
    // Ensure dark mode is always active
    document.documentElement.classList.add('dark');
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 transition-colors duration-200">
      <div className="container mx-auto px-4">
        <ScannerUI />
      </div>
    </div>
  );
}

export default App;
