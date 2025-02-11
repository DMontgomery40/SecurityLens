import React from 'react';
import { ArrowLeft } from 'lucide-react';

const InfoPanel = ({ selectedVulnerability, isScanning, onBackToResults, isMobile }) => {
  // If no vulnerability is selected, show an overview
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
      </div>
    );
  }

  // If a vulnerability is selected, you could show minimal content or something else
  return (
    <div className="bg-gray-800 rounded-lg p-6 sticky top-4">
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
