import React, { useState, useEffect } from 'react';

function ProgressBar() {
  // Initialize with 0. Ensure your API returns non-zero total when scanning starts.
  const [progress, setProgress] = useState({ scanned: 0, total: 0 });

  useEffect(() => {
    async function fetchProgress() {
      try {
        // Assuming your Netlify function or API endpoint is at /api/progress
        const response = await fetch('/api/progress');
        const data = await response.json();
        console.log('Progress API response:', data);
        // Make sure data.scanned and data.total are valid numbers
        setProgress({
          scanned: typeof data.scanned === 'number' ? data.scanned : 0,
          total: typeof data.total === 'number' ? data.total : 0,
        });
      } catch (error) {
        console.error('Error fetching progress:', error);
      }
    }

    // Poll every 2 seconds (adjust as needed)
    const intervalId = setInterval(fetchProgress, 2000);

    // Clean up on unmount
    return () => clearInterval(intervalId);
  }, []);

  return (
    <div>
      <p>{`fetching: ${progress.scanned} of ${progress.total}`}</p>
      {/* Add any additional UI, like a visual progress bar */}
    </div>
  );
}

export default ProgressBar; 