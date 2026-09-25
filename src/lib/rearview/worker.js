// Parses agent transcripts off the main thread. This worker makes no network
// requests; everything it reads stays in the tab.

import { parseTranscript } from './parse.js';
import { buildLedger } from './ledger.js';

const MAX_FILE_BYTES = 200 * 1024 * 1024;

self.onmessage = async (event) => {
  const { files = [], samples = [] } = event.data || {};
  const sessions = [];
  let done = 0;
  let bytes = 0;
  let skipped = 0;
  const total = files.length + samples.length;

  for (const sample of samples) {
    const session = parseTranscript(sample.text, { filename: sample.name });
    if (session) sessions.push(session);
    done += 1;
  }

  for (const file of files) {
    try {
      if (file.size > MAX_FILE_BYTES) {
        skipped += 1;
      } else {
        const session = parseTranscript(await file.text(), { filename: file.name });
        if (session) sessions.push(session);
        else skipped += 1;
      }
    } catch {
      skipped += 1;
    }
    done += 1;
    bytes += file.size || 0;
    if (done % 10 === 0) self.postMessage({ type: 'progress', done, total, bytes });
  }

  self.postMessage({ type: 'done', ledger: buildLedger(sessions), skipped, total, bytes });
};
