import React from 'react';
import { proactiveControls } from '../lib/proactiveControls';
import { ArrowLeft } from 'lucide-react';

const InfoPanel = ({ selectedVulnerability, isScanning, onBackToResults, isMobile }) => {
  // Show overview content when no vulnerability is selected
  if (!selectedVulnerability) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 sticky top-4">
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
                <p className="text-sm mt-1">Whoa! These need immediate attention - they're like leaving your front door wide open! 🚨</p>
              </div>
              <div className="p-3 bg-gray-700/50 rounded-lg border border-orange-500/20">
                <span className="text-orange-500 font-semibold">HIGH:</span>
                <p className="text-sm mt-1">Pretty serious stuff - like having a weak lock on that door. Let's fix these soon! ⚠️</p>
              </div>
              <div className="p-3 bg-gray-700/50 rounded-lg border border-yellow-500/20">
                <span className="text-yellow-500 font-semibold">MEDIUM:</span>
                <p className="text-sm mt-1">Not urgent, but definitely worth improving - think of it as upgrading your security system. 🔍</p>
              </div>
              <div className="p-3 bg-gray-700/50 rounded-lg border border-blue-500/20">
                <span className="text-blue-500 font-semibold">LOW:</span>
                <p className="text-sm mt-1">Good practices to learn - like adding a security camera to an already secure house. 💡</p>
              </div>
            </div>
          </section>

          <section>
            <h3 className="text-lg font-semibold mb-3">Pro Tips for Young Security Researchers</h3>
            <ul className="space-y-3">
              <li className="flex items-start gap-2">
                <span className="text-blue-400">🔍</span>
                <span>Look at each finding carefully - real security experts always dig deeper!</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400">💻</span>
                <span>Check out the code examples - they show you exactly what to look for.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400">📚</span>
                <span>Follow the protection guides - they're like cheat codes for security!</span>
              </li>
            </ul>
          </section>
        </div>
      </div>
    );
  }

  // Show proactive controls for selected vulnerability
  const control = proactiveControls[selectedVulnerability.type];
  
  return (
    <div className="bg-gray-800 rounded-lg p-6 sticky top-4">
      {/* Mobile back button */}
      {isMobile && (
        <button
          onClick={onBackToResults}
          className="lg:hidden mb-4 flex items-center text-blue-400 hover:text-blue-300"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Results
        </button>
      )}

      <h2 className="text-xl font-bold mb-4">{control?.title || 'Security Control'}</h2>
      <div 
        className="prose prose-invert prose-pre:bg-gray-900 prose-pre:text-gray-100 max-w-none"
        dangerouslySetInnerHTML={{ __html: control?.content || 'Loading...' }}
      />

      {/* Floating back button for long content */}
      {isMobile && (
        <button
          onClick={onBackToResults}
          className="lg:hidden fixed bottom-4 right-4 bg-blue-600 text-white p-3 rounded-full shadow-lg hover:bg-blue-700 transition-colors z-50"
          aria-label="Back to results"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
      )}

      <style jsx>{`
        .prose pre {
          margin: 0;
          padding: 1rem;
          border-radius: 0.375rem;
        }
        .prose code {
          color: inherit;
          font-weight: inherit;
          font-size: 0.875em;
        }
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
      `}</style>
    </div>
  );
};

export default InfoPanel; 