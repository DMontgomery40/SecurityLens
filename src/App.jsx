import React, { useEffect } from 'react';
import Decoder from './components/Decoder';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from './components/Home';

function App() {
  useEffect(() => {
    // Ensure dark mode is always active
    document.documentElement.classList.add('dark');
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/secret" element={<Decoder />} />
      </Routes>
    </Router>
  );
}

export default App;
