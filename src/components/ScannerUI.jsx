import React, { useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import VulnerabilityScanner from '../lib/scanner';
import ScanButton from './ScanButton';
import ScanResults from './ScanResults';

const ScannerUI = () => {
    const [scanResults, setScanResults] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [error, setError] = useState(null);

    const handleFileSelect = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        setScanning(true);
        setError(null);

        try {
            const scanner = new VulnerabilityScanner();
            const content = await file.text();
            const findings = await scanner.scanFile(content, file.name);
            const report = scanner.generateReport(findings);
            setScanResults(report);
        } catch (err) {
            setError(err.message);
        } finally {
            setScanning(false);
        }
    };

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold">Plugin Vulnerability Scanner</h1>
                    <p className="text-gray-600">Upload a JavaScript file to scan for security vulnerabilities</p>
                </div>
                <div>
                    <input
                        type="file"
                        accept=".js,.ts,.jsx,.tsx"
                        onChange={handleFileSelect}
                        className="hidden"
                        id="fileInput"
                    />
                    <label
                        htmlFor="fileInput"
                        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 cursor-pointer disabled:opacity-50"
                    >
                        {scanning ? 'Scanning...' : 'Select File'}
                    </label>
                </div>
            </div>

            {error && (
                <div className="mb-4 p-4 bg-red-100 text-red-700 rounded">
                    <div className="flex items-center">
                        <AlertTriangle className="h-5 w-5 mr-2" />
                        <div>
                            <div className="font-bold">Error</div>
                            <div>{error}</div>
                        </div>
                    </div>
                </div>
            )}

            <ScanResults results={scanResults} />
        </div>
    );
};

export default ScannerUI;