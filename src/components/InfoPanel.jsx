import React, { useEffect, useRef } from 'react';
import { ArrowLeft, Sword, Shield } from 'lucide-react';
import { proactiveControls } from '../lib/proactiveControls';

const InfoPanel = ({ selectedVulnerability, onBackToResults, isMobile }) => {
  const infoPanelRef = useRef(null);

  // Default "welcome" content
  const WelcomeContent = () => (
    <div className="prose prose-invert">
      <h2 className="text-2xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-600 bg-clip-text text-transparent">
        Your Journey into Security Starts Here! 🚀
      </h2>
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
            <p className="text-sm mt-1">Immediate attention—like leaving your door wide open! 🚨</p>
          </div>
          <div className="p-3 bg-gray-700/50 rounded-lg border border-orange-500/20">
            <span className="text-orange-500 font-semibold">HIGH:</span>
            <p className="text-sm mt-1">Serious—like a weak lock on the door. Fix soon! ⚠️</p>
          </div>
          <div className="p-3 bg-gray-700/50 rounded-lg border border-yellow-500/20">
            <span className="text-yellow-500 font-semibold">MEDIUM:</span>
            <p className="text-sm mt-1">Worth improving—like upgrading your security system. 🔍</p>
          </div>
          <div className="p-3 bg-gray-700/50 rounded-lg border border-blue-500/20">
            <span className="text-blue-500 font-semibold">LOW:</span>
            <p className="text-sm mt-1">Good practices—like adding a camera. 💡</p>
          </div>
        </div>
      </section>

      <section>
        <h3 className="text-lg font-semibold mb-3">Pro Tips for Young Security Researchers</h3>
        <ul className="space-y-3">
          <li className="flex items-start gap-2">
            <span className="text-blue-400">🔍</span>
            <span>Look at each finding carefully—real security experts always dig deeper!</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-400">💻</span>
            <span>Check out the code examples—they show you exactly what to look for.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-400">📚</span>
            <span>Follow the protection guides—they're like cheat codes for security!</span>
          </li>
        </ul>
      </section>
    </div>
  );

  // The Red/Blue team vulnerability guide
  const VulnerabilityGuide = ({ vulnerability }) => {
    const control = proactiveControls[vulnerability.type];
    if (!control) {
      return (
        <div className="mt-4 p-4 bg-red-900/30 rounded-lg">
          <p className="text-red-300">No guide found for this vulnerability type.</p>
        </div>
      );
    }

    return (
      <div className="space-y-6">
        {/* Red Team Section */}
        <div className="bg-gray-800/50 rounded-lg p-4 border border-red-700/30">
          <div className="flex items-center gap-2 mb-4">
            <Sword className="w-5 h-5 text-red-400" />
            <h3 className="text-lg font-semibold text-red-400">Red Team Perspective</h3>
          </div>
          <div 
            className="prose prose-invert"
            dangerouslySetInnerHTML={{ __html: control.redTeam || '<p>Red team content coming soon...</p>' }}
          />
        </div>

        {/* Blue Team Section */}
        <div className="bg-gray-800/50 rounded-lg p-4 border border-blue-700/30">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold text-blue-400">Blue Team Defense</h3>
          </div>
          <div
            className="prose prose-invert"
            dangerouslySetInnerHTML={{ __html: control.blueTeam || '<p>Blue team content coming soon...</p>' }}
          />
        </div>
      </div>
    );
  };

  // Called when user clicks "Back to Results"
  const handleBackClick = () => {
    onBackToResults();
  };

  // For desktop: pin the panel if user scrolls
  useEffect(() => {
    if (!infoPanelRef.current) return;
    if (isMobile) return; // no pinned behavior on mobile

    const handleScroll = () => {
      // Only pin if there's a selected vulnerability
      if (!selectedVulnerability) return;

      const vulnId = `vuln-${selectedVulnerability.type}-${selectedVulnerability.files[0]}`;
      const vulnElement = document.getElementById(vulnId);
      if (!vulnElement || !infoPanelRef.current) return;

      const vulnRect = vulnElement.getBoundingClientRect();

      // If the top of the card is above 16px from top, pin the panel
      if (vulnRect.top < 16) {
        infoPanelRef.current.style.top = '16px';
      } else {
        // Otherwise align with the vulnerability's top
        infoPanelRef.current.style.top = `${vulnRect.top}px`;
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [selectedVulnerability, isMobile]);

  return (
    <div
      ref={infoPanelRef}
      id="infoPanel"
      // Reduced padding from p-6 → p-4
      className={`bg-gray-800 rounded-lg p-4 ${
        isMobile ? 'mt-8' : 'sticky top-4'
      }`}
      style={{ transition: 'top 0.3s ease' }}
    >
      {selectedVulnerability && (
        <button
          onClick={handleBackClick}
          className="mb-4 flex items-center text-blue-400 hover:text-blue-300"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Results
        </button>
      )}

      {selectedVulnerability ? (
        <>
          <h2 className="text-xl font-bold mb-2">
            {selectedVulnerability.description}
          </h2>
          <VulnerabilityGuide vulnerability={selectedVulnerability} />
        </>
      ) : (
        <WelcomeContent />
      )}

      <style>
        {`
          /* Force horizontal scrolling in <pre>/<code> blocks */
          .prose pre {
            margin: 0.5rem 0;
            padding: 0.75rem;
            border-radius: 0.25rem;
            background-color: rgba(0, 0, 0, 0.2);
            overflow-x: auto;       /* horizontal scroll if needed */
            white-space: pre;       /* preserve whitespace */
          }
          .prose code {
            color: inherit;
            font-weight: inherit;
            font-size: 0.875em;
            white-space: pre-wrap;
          }
          .prose pre code {
            white-space: pre;       /* ensures code lines don't wrap */
          }

          /* Example-block styling */
          .example-block {
            margin: 1rem 0;
            border-radius: 0.5rem;
            overflow: hidden;
          }
          .example-label {
            padding: 0.5rem 1rem;
            font-weight: 500;
            background: rgba(0,0,0,0.2);
          }
          .code-block.bad {
            border-left: 4px solid #ef4444;
          }
          .code-block.good {
            border-left: 4px solid #22c55e;
          }
        `}
      </style>
    </div>
  );
};

export default InfoPanel;
