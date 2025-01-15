import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import ScannerUI from './components/ScannerUI';
import Decoder from './components/Decoder';

const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ScannerUI />} />
        <Route path="/secret" element={<Decoder />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
