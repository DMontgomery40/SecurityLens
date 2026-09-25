// View-model helpers shared by the lens components.

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };
export const INSTRUCTION_KINDS = new Set([
  'hidden-instruction',
  'instruction-in-untrusted',
  'invisible-payload',
  'attribute-instruction',
  'tool-description-instruction',
  'instruction-via-spoofable-voice'
]);

export function topSeverity(findings) {
  return findings.reduce((best, finding) => (SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf(best) ? finding.severity : best), 'info');
}

export function findingsBySegment(report) {
  const map = new Map();
  for (const finding of report.findings || []) {
    if (!finding.segmentId) continue;
    if (!map.has(finding.segmentId)) map.set(finding.segmentId, []);
    map.get(finding.segmentId).push(finding);
  }
  return map;
}

const BASIS_TEXT = {
  inferred: 'Looks like user content',
  policy: 'Declared by the policy',
  attribute: 'Marked untrusted in markup',
  embed: 'Embedded from another site'
};

export function speakerFor(block, report) {
  if (block.zone === 'voice') {
    return { name: 'The site', basis: report.mode === 'declared' ? 'Per the policy' : null };
  }
  if (block.zone === 'hidden') {
    return { name: 'Hidden', basis: block.region?.reason || 'Not visible to people' };
  }
  const region = block.region;
  const name = region && region.basis === 'inferred' ? region.label : 'Someone else';
  return { name, basis: BASIS_TEXT[region?.basis] || BASIS_TEXT[block.segments[0]?.basis] || null };
}

export function buildBlocks(report) {
  const regions = new Map((report.regions || []).map((region) => [region.id, region]));
  const blocks = [];
  for (const segment of report.segments || []) {
    const key = segment.zone === 'voice' ? 'voice' : `${segment.zone}:${segment.regionId}`;
    const last = blocks[blocks.length - 1];
    if (last && last.groupKey === key) {
      last.segments.push(segment);
    } else {
      blocks.push({ key: `${key}:${blocks.length}`, groupKey: key, zone: segment.zone, region: regions.get(segment.regionId) || null, segments: [segment] });
    }
  }
  return blocks;
}

export function speakerShares(report) {
  const chars = report.summary?.chars || { voice: 0, untrusted: 0, hidden: 0 };
  const total = chars.voice + chars.untrusted + chars.hidden;
  const share = (value) => (total ? Math.round((value / total) * 1000) / 10 : 0);
  return { total, voice: share(chars.voice), untrusted: share(chars.untrusted), hidden: share(chars.hidden), chars };
}
