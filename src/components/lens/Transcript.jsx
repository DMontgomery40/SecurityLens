import React, { useMemo, useState } from 'react';
import { buildBlocks, findingsBySegment, speakerFor, topSeverity, SEVERITY_LABEL } from './model.js';

const INITIAL_BLOCKS = 240;

function Passage({ segment, findings }) {
  const flagged = findings.length > 0;
  const severity = flagged ? topSeverity(findings) : null;
  const decodedFinding = findings.find((finding) => finding.decoded);
  const decoded = decodedFinding?.decoded;
  const decodedLabel = decodedFinding?.decodedFrom === 'base64' ? 'The base64 text decodes to:' : 'Invisible characters decode to:';
  const className = ['sl-passage', segment.quoted ? 'sl-passage-quoted' : '', flagged ? `sl-passage-flagged sl-sev-${severity}` : '']
    .filter(Boolean)
    .join(' ');

  return (
    <p id={`seg-${segment.id}`} className={className} tabIndex={flagged ? -1 : undefined}>
      {flagged && (
        <span className={`sl-flag sl-sevtext-${severity}`}>
          <span className="sl-sev">{SEVERITY_LABEL[severity]}</span>
          <span>{findings[0].title}</span>
        </span>
      )}
      {flagged && <br />}
      {segment.text}
      {decoded && (
        <>
          <br />
          <span className="sl-small">
            {decodedLabel} <strong style={{ color: 'var(--ink)' }}>{decoded}</strong>
          </span>
        </>
      )}
    </p>
  );
}

export default function Transcript({ report, limit = INITIAL_BLOCKS, label = 'Page transcript by speaker' }) {
  const blocks = useMemo(() => buildBlocks(report), [report]);
  const bySegment = useMemo(() => findingsBySegment(report), [report]);
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? blocks : blocks.slice(0, limit);

  if (blocks.length === 0) {
    return (
      <div className="sl-panel-pad">
        <p style={{ margin: 0 }}>There is no readable text in this page's HTML.</p>
        {report.coverage?.scriptsNotExecuted && (
          <p className="sl-support" style={{ margin: '8px 0 0' }}>
            The page probably builds its content with JavaScript, which the lens does not run.
          </p>
        )}
      </div>
    );
  }

  return (
    <>
      <ol className="sl-transcript" aria-label={label}>
        {visible.map((block) => {
          const speaker = speakerFor(block, report);
          return (
            <li key={block.key} className={`sl-block sl-block-${block.zone}`}>
              <div className="sl-speaker">
                <span className="sl-speaker-name">{speaker.name}</span>
                {speaker.basis && <span className="sl-speaker-basis">{speaker.basis}</span>}
              </div>
              <div className="sl-passages">
                {block.segments.map((segment) => (
                  <Passage key={segment.id} segment={segment} findings={bySegment.get(segment.id) || []} />
                ))}
              </div>
            </li>
          );
        })}
      </ol>
      {blocks.length > visible.length && (
        <div className="sl-more">
          <button type="button" className="sl-button sl-button-quiet" onClick={() => setExpanded(true)}>
            Show the remaining {blocks.length - visible.length} passages
          </button>
        </div>
      )}
    </>
  );
}
