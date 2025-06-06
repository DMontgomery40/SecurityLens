import React, { useState, useEffect } from 'react';
import { ArrowLeft } from 'lucide-react';
import { vulnerabilityGuides } from '../lib/proactiveControlsData';

const InfoPanel = ({ selectedVulnerability, isScanning, onBackToResults, isMobile }) => {
  const [showAllGuides, setShowAllGuides] = useState(false);

  // Helper to toggle guide list
  const handleToggleGuides = () => setShowAllGuides(!showAllGuides);

  // Ensure long code blocks wrap & scroll within InfoPanel
  useEffect(() => {
    if (typeof document === 'undefined') return;
    if (document.getElementById('info-panel-wrap-style')) return; // already added

    const style = document.createElement('style');
    style.id = 'info-panel-wrap-style';
    style.innerHTML = `
      #infoPanel .prose pre, 
      #infoPanel .prose code, 
      #infoPanel pre, 
      #infoPanel code {
        white-space: pre-wrap !important;
        word-break: break-word !important;
        overflow-x: auto !important;
        max-width: 100%;
        box-sizing: border-box;
      }
      #infoPanel hr { border-color: #334155; margin: 1.5rem 0; }
      #infoPanel a { color:#3b82f6; text-decoration: underline; }
      #infoPanel a:hover { color:#60a5fa; }
      #infoPanel .prose p { margin:0.6rem 0; line-height:1.7; }
      #infoPanel .prose { font-size:0.95rem; }
      #infoPanel .prose li { margin-bottom:0.4rem; }
      #infoPanel .prose strong { display:inline-block; margin-top:0.6rem; }
    `;
    document.head.appendChild(style);
    return () => { document.head.removeChild(style); };
  }, []);

  // If no vulnerability is selected, show an overview
  if (!selectedVulnerability) {
    if (showAllGuides) {
      return (
        <div id="infoPanel" style={{ resize: 'horizontal', overflow: 'auto', minWidth: '260px', maxWidth: '750px' }} className="bg-gray-800 rounded-lg p-6 overflow-y-auto max-h-[80vh] sticky top-4">
          <button
            onClick={handleToggleGuides}
            className="mb-4 text-blue-400 hover:text-blue-300 text-sm underline"
          >
            ← Back to Overview
          </button>
          <h2 className="text-2xl font-bold mb-4 text-blue-300">All Protection Guides</h2>
          <div className="space-y-4">
            {Object.entries(vulnerabilityGuides).map(([key, guide]) => (
              <details key={key} className="border border-gray-700 rounded-lg">
                <summary className="cursor-pointer select-none px-4 py-2 bg-gray-700/50 hover:bg-gray-700 font-medium">
                  {guide.title || key}
                </summary>
                <div className="p-4 space-y-6 bg-gray-800/50">
                  {guide.content && (
                    <div className="prose prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: guide.content }} />
                  )}
                  {guide.redTeam && (
                    <div className="prose prose-invert max-w-none border border-red-500/30 rounded p-4" dangerouslySetInnerHTML={{ __html: guide.redTeam }} />
                  )}
                  {(guide.blueTeamWindows || guide.blueTeamMac || guide.blueTeamLinux) && (
                    <div className="space-y-3">
                      {guide.blueTeamWindows && (
                        <div className="prose prose-invert max-w-none border border-blue-500/20 rounded p-4" dangerouslySetInnerHTML={{ __html: guide.blueTeamWindows }} />
                      )}
                      {guide.blueTeamMac && (
                        <div className="prose prose-invert max-w-none border border-blue-500/20 rounded p-4" dangerouslySetInnerHTML={{ __html: guide.blueTeamMac }} />
                      )}
                      {guide.blueTeamLinux && (
                        <div className="prose prose-invert max-w-none border border-blue-500/20 rounded p-4" dangerouslySetInnerHTML={{ __html: guide.blueTeamLinux }} />
                      )}
                    </div>
                  )}
                </div>
              </details>
            ))}
          </div>
        </div>
      );
    }

    return (
      <div id="infoPanel" style={{ resize: 'horizontal', overflow: 'auto', minWidth: '260px', maxWidth: '750px' }} className="bg-gray-800 rounded-lg p-6 sticky top-4">
        <h2 className="text-2xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-600 bg-clip-text text-transparent">
          Your Journey into Security Starts Here! 🚀
        </h2>

        <div className="prose prose-invert">
          <section className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Ready to Be a Security Hero?</h3>
            <p className="text-gray-300">
              Ever wondered how hackers find vulnerabilities? Want to learn how to protect websites and apps? 
              You're in the right place! Drop in your code or website, and let's discover security together.
            </p>
          </section>

          <section className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Understanding Your Discoveries</h3>
            <div className="space-y-3">
              <div className="p-3 bg-gray-700/50 rounded-lg border border-red-500/20">
                <span className="text-red-500 font-semibold">CRITICAL:</span>
                <p className="text-sm mt-1">These need immediate attention - like leaving the front door wide open! 🚨</p>
              </div>
              <div className="p-3 bg-gray-700/50 rounded-lg border border-orange-500/20">
                <span className="text-orange-500 font-semibold">HIGH:</span>
                <p className="text-sm mt-1">Pretty serious - fix these soon! ⚠️</p>
              </div>
              <div className="p-3 bg-gray-700/50 rounded-lg border border-yellow-500/20">
                <span className="text-yellow-500 font-semibold">MEDIUM:</span>
                <p className="text-sm mt-1">Worth improving - think about stronger locks. 🔍</p>
              </div>
              <div className="p-3 bg-gray-700/50 rounded-lg border border-blue-500/20">
                <span className="text-blue-500 font-semibold">LOW:</span>
                <p className="text-sm mt-1">Not urgent, but good to address for best practices. 💡</p>
              </div>
            </div>
          </section>

          <section>
            <h3 className="text-lg font-semibold mb-3">Pro Tips for Security Researchers</h3>
            <ul className="space-y-3">
              <li className="flex items-start gap-2">
                <span className="text-blue-400">🔍</span>
                <span>Look at each finding carefully - real experts dig deeper!</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400">💻</span>
                <span>Check out code examples - they show you what to look for.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400">📚</span>
                <span>Use the protection guides - they're like cheat codes for security!</span>
              </li>
            </ul>
          </section>
        </div>
        <button
          onClick={handleToggleGuides}
          className="mt-4 inline-block text-blue-400 hover:text-blue-300 underline text-sm"
        >
          Browse All Protection Guides
        </button>
      </div>
    );
  }

  // If a vulnerability is selected, you could show minimal content or something else
  return (
    <div style={{ resize: 'horizontal', overflow: 'auto', minWidth: '260px', maxWidth: '750px' }} className="bg-gray-800 rounded-lg p-6 sticky top-4">
      {isMobile && (
        <button
          onClick={onBackToResults}
          className="lg:hidden mb-4 flex items-center text-blue-400 hover:text-blue-300"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Results
        </button>
      )}
      <h2 className="text-xl font-bold mb-4">Security Control</h2>
      <p className="text-gray-300">
        Select "View Protection Guide" on a result to see in-depth Red/Blue Team content here.
      </p>

      {/* Official CVE Details Link */}
      {selectedVulnerability && selectedVulnerability.type && (
        <div className="mt-6">
          <h3 className="text-lg font-bold text-blue-300 mb-2">
            Recent CVEs for {selectedVulnerability.type}
          </h3>
          <a
            href={`https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${encodeURIComponent(selectedVulnerability.type)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 hover:text-blue-300 underline"
          >
            View recent CVEs for {selectedVulnerability.type}
          </a>
        </div>
      )}
    </div>
  );
};

export default InfoPanel;
