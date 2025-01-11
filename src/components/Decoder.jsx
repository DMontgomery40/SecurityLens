import React, { useState } from 'react';

const Decoder = () => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [showLink, setShowLink] = useState(false);

  const handleDecode = () => {
    try {
      const decoded = atob(input);
      setOutput(
        'hashcat (v6.2.6) starting in decode mode...\n' +
        '\n' +
        '* Device #1: NVIDIA GeForce RTX 3080, 9728/10018 MB, 68MCU\n' +
        '\n' +
        'Watchdog: Temperature abort trigger set to 90c\n' +
        'Initializing backend runtime for device #1...'
      );
      
      setTimeout(() => {
        setOutput(prev => prev + 
          '\nClew..........: 0x7f3a9c2d\n' +
          'Type..........: Base64\n' +
          'Target........: b64.encoded.data\n' +
          '\n' +
          'Started: Thu Mar 14 20:23:11 2024\n' +
          'Decoded.......: 1/1 (100.00%)\n' +
          'Progress......: 4096/4096 (100.00%)\n' +
          'Time.Estimated: 0 secs\n' +
          'Recovered.....: 1/1 (100.00%) Digests'
        );
        setTimeout(() => {
          setOutput(prev => prev + 
            '\n\nSession.Name...: decoder\n' +
            'Status........: Cracked\n' +
            'Hash.Type.....: Base64\n' +
            'Time.Started..: 0 secs\n' +
            'Time.Estimated: 0 secs\n' +
            'Kernel.Feature: Pure Kernel\n' +
            '\n' +
            'Starting.Dict.: /usr/share/wordlists/rockyou.txt\n' +
            'Candidates.#1.: $plaintext'
          );
          setTimeout(() => {
            setOutput(prev => prev + 
              '\n\nHost.Compute..: 2439.5 kH/s\n' +
              'Elapsed........: 0.41 secs\n' +
              '\n' +
              'Session completed. Proceed to next stage:'
            );
            setShowLink(true);
          }, 800);
        }, 600);
      }, 400);
      
    } catch (e) {
      setOutput('> Error: Invalid base64 input');
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="bg-gray-800 rounded p-6 font-mono border border-gray-700">
          <div className="mb-4">
            <div className="flex items-center gap-2 text-green-400 mb-2">
              <span className="text-xs">$</span>
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleDecode()}
                placeholder="Paste your secret code here..."
                className="bg-transparent border-none outline-none w-full focus:ring-0"
              />
            </div>
            {output && (
              <div className="text-blue-400 whitespace-pre-wrap break-all">
                {output}
                {showLink && (
                  <div className="mt-4">
                    <a 
                      href="https://github.com/ghostsecurity/reaper/blob/main/docs/how-to-hack-ghostbank.md"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-green-400 hover:text-green-300 no-underline hover:underline"
                    >
                      &gt; Click here to continue your journey...
                    </a>
                  </div>
                )}
              </div>
            )}
          </div>
          <button
            onClick={handleDecode}
            className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
          >
            Decode
          </button>
        </div>
      </div>
    </div>
  );
};

export default Decoder; 