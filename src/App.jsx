import React, { useState, useEffect } from 'react';
import ScannerUI from './components/ScannerUI';

function App() {
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    const storedTheme = localStorage.getItem('theme');
    if (storedTheme === 'dark') {
      setDarkMode(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  const toggleDarkMode = () => {
    if (darkMode) {
      setDarkMode(false);
      localStorage.setItem('theme', 'light');
      document.documentElement.classList.add('dark');
    } else {
      setDarkMode(true);
      localStorage.setItem('theme', 'dark');
      document.documentElement.classList.add('dark');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
      <div className="container mx-auto px-4">
        <div className="flex justify-end pt-4">
          
        </div>
        <ScannerUI />
      </div>
    </div>
  );
}

export default App;