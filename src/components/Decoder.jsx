import React, { useState } from 'react';

const Decoder = () => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [showLink, setShowLink] = useState(false);

  const handleDecode = () => {
    try {
      // Attempt to decode Base64
      const decoded = atob(input);

      /* 
        Greg -
        Thanks again for our conversation. 
        This final step in the scavenger hunt 
        shows I can be fun + technically solid 
        while staying kid-friendly.

        – David
      */

      // Added security easter eggs in the console output for Greg
      
      // Terminal-like output sequence
      setOutput(
        'john (v1.9.0-jumbo-1) starting...\n' +
        '=================================================\n' +
        '* Device #1: NVIDIA GeForce RTX 3080, 9728/10018 MB, 68MCU\n' +
        '* OSINT module: ShadowFinder™ initialized\n' +
        'Watchdog: Temperature abort trigger set to 90c\n' +
        'Initializing backend runtime for device #1...\n'
      );

      setTimeout(() => {
        setOutput(prev => prev +
          '\nModule.Loaded.......: Base64 Decoder (Mode #2400)\n' +
          'Input.Format........: base64\n' +
          'Session.Name........: specter_recon\n' +
          'CVE.Check...........: No Log4Shell vulnerabilities detected\n' +
          'Started.............: Thu Mar 14 20:23:11 2024\n' +
          'Operation...........: Direct transformation\n' +
          '=================================================\n'
        );

        setTimeout(() => {
          setOutput(prev => prev +
            '\nProcessing.Progress.: 100%\n' +
            'Buffer.Size.........: 4.8 KB\n' +
            'Memcheck.Status.....: CLEAN (0xDEADBEEF -> 0xCAFEBABE)\n' +
            'Ghost.Security......: No malware detected in payload\n' +
            'DEF_CON.Level.......: BLUE (safe for educational use)\n' +
            'Verification........: Completed\n' +
            '=================================================\n'
          );

          setTimeout(() => {
            setOutput(prev => prev +
              `\nDecoded.Output......: ${decoded}\n` +
              'Status..............: Success\n' +
              'Kernel.Performance..: 8.2 GB/s\n' +
              'CPU.Utilization.....: 23%\n' +
              'Reaper.Status.......: online\n' +
              'Elapsed.............: 0.42 secs\n' +
              '\n[Ghost@Security ~]$ sudo ./validate --token 0xC001D00D\n' +
              'Validation successful. Proceed to the next stage:'
            );
            setShowLink(true);
          }, 800);
        }, 600);
      }, 400);

    } catch (e) {
      setOutput('> Error: Invalid base64 input\n> Hint: Try running strings on the binary first');
    }
  };

  return (
    <div className="min-h-screen bg-black text-gray-100 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="rounded p-6 font-mono border border-gray-700">
          <div className="mb-4">
            <div className="flex items-center gap-2 text-green-500 mb-2">
              <span className="text-xs">$</span>
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleDecode();
                  } else if (e.ctrlKey && e.key === 'c') {
                    // Easter egg - shows a special message when Ctrl+C is pressed
                    const currentVal = e.target.value;
                    if (currentVal === '') {
                      setOutput('> Security through obscurity is not security at all.\n> - Ghost Security Philosophy');
                    }
                  }
                }}
                placeholder="Paste your base64 code here..."
                className="bg-transparent border-none outline-none w-full focus:ring-0 placeholder-gray-500"
              />
            </div>
            {output && (
              <div className="text-green-400 whitespace-pre-wrap break-all">
                {output}
                {showLink && (
                  <div className="mt-4 text-green-300">
                    &gt;{' '}
                    <a
                      href="https://github.com/ghostsecurity/reaper/blob/main/docs/how-to-hack-ghostbank.md"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:underline"
                      // Easter egg in the DOM that would be visible in developer tools
                      data-ghost-token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMzM3IiwibmFtZSI6Ikdob3N0IFNlY3VyaXR5IENhbmRpZGF0ZSIsImNsZWFyYW5jZSI6InRvcF9zZWNyZXQifQ"
                    >
                      Click here to continue your journey...
                    </a>
                  </div>
                )}
              </div>
            )}
          </div>
          <button
            onClick={handleDecode}
            className="px-4 py-2 bg-gray-800 text-green-400 border border-green-400 rounded hover:bg-gray-700 transition-colors"
          >
            Decode
          </button>
          {/* Hidden comment for security researchers */}
          {/* FLAG{Gh0st_S3cur1ty_H1r3_M3} */}
        </div>
      </div>
    </div>
  );
};

export default Decoder;
