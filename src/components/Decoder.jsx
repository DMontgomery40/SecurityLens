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

      // Terminal-like output sequence
      setOutput(
        'hashcat (v6.2.6) starting in --base64 mode...\n' +
        '=================================================\n' +
        '* Device #1: NVIDIA GeForce RTX 3080, 9728/10018 MB, 68MCU\n' +
        'Watchdog: Temperature abort trigger set to 90c\n' +
        'Initializing backend runtime for device #1...\n'
      );

      setTimeout(() => {
        setOutput(prev => prev +
          '\nPlugin.Base64........: Loaded (Mode #2400)\n' +
          'Hash.Target.........: b64-encoded-data\n' +
          'Session.Name........: blackhat_edu\n' +
          'Started.............: Thu Mar 14 20:23:11 2024\n' +
          'Probing dictionary..: /usr/share/wordlists/rockyou.txt\n' +
          '=================================================\n'
        );

        setTimeout(() => {
          setOutput(prev => prev +
            '\nProgress............: 1337/1337 (100.00%)\n' +
            'Time.Estimated......: 0 secs\n' +
            'Recovered.Digests...: 1/1 (100.00%)\n' +
            'Recovered.Plains....: 1/1 (100.00%)\n' +
            '=================================================\n'
          );

          setTimeout(() => {
            setOutput(prev => prev +
              `\nDecoded.Output......: ${decoded}\n` +
              'Status..............: Cracked\n' +
              'Kernel.Feature......: Pure Kernel\n' +
              'Host.Compute........: 2600.0 kH/s\n' +
              'Elapsed.............: 0.42 secs\n' +
              '\nSession completed. Proceed to the next stage:'
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
                onKeyDown={(e) => e.key === 'Enter' && handleDecode()}
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
        </div>
      </div>
    </div>
  );
};
