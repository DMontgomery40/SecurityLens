import React from 'react';

// Minimal Markdown renderer for first-party documents. Supports the subset
// the spec uses and builds React elements, so no raw HTML is injected.

function slug(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function inline(text, keyPrefix) {
  const nodes = [];
  const pattern = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)\s]+\))/g;
  let last = 0;
  let match;
  let index = 0;
  while ((match = pattern.exec(text))) {
    if (match.index > last) nodes.push(text.slice(last, match.index));
    const token = match[0];
    const key = `${keyPrefix}-${index++}`;
    if (token.startsWith('`')) nodes.push(<code key={key} className="sl-inline-code">{token.slice(1, -1)}</code>);
    else if (token.startsWith('**')) nodes.push(<strong key={key}>{inline(token.slice(2, -2), key)}</strong>);
    else {
      const [, label, href] = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      const safe = /^(https?:|\/|#)/.test(href) ? href : '#';
      nodes.push(<a key={key} href={safe}>{label}</a>);
    }
    last = match.index + token.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function splitRow(line) {
  return line.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim());
}

export default function Markdown({ source }) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    const key = `b${blocks.length}`;

    if (!line.trim()) {
      index += 1;
      continue;
    }

    if (line.startsWith('```')) {
      const body = [];
      index += 1;
      while (index < lines.length && !lines[index].startsWith('```')) body.push(lines[index++]);
      index += 1;
      blocks.push(<pre key={key} className="sl-code"><code>{body.join('\n')}</code></pre>);
      continue;
    }

    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    if (heading) {
      const Tag = `h${heading[1].length}`;
      blocks.push(<Tag key={key} id={slug(heading[2])}>{inline(heading[2], key)}</Tag>);
      index += 1;
      continue;
    }

    if (line.trim().startsWith('|') && index + 1 < lines.length && /^\s*\|?\s*-{3,}/.test(lines[index + 1])) {
      const header = splitRow(line);
      index += 2;
      const rows = [];
      while (index < lines.length && lines[index].trim().startsWith('|')) rows.push(splitRow(lines[index++]));
      blocks.push(
        <table key={key}>
          <thead><tr>{header.map((cell, i) => <th key={i}>{inline(cell, `${key}h${i}`)}</th>)}</tr></thead>
          <tbody>{rows.map((row, r) => <tr key={r}>{row.map((cell, i) => <td key={i}>{inline(cell, `${key}r${r}c${i}`)}</td>)}</tr>)}</tbody>
        </table>
      );
      continue;
    }

    const listMatch = line.match(/^(\s*)([-*]|\d+\.)\s+/);
    if (listMatch) {
      const ordered = /\d/.test(listMatch[2]);
      const items = [];
      while (index < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*([-*]|\d+\.)\s+/, ''));
        index += 1;
      }
      const List = ordered ? 'ol' : 'ul';
      blocks.push(<List key={key}>{items.map((item, i) => <li key={i}>{inline(item, `${key}i${i}`)}</li>)}</List>);
      continue;
    }

    const paragraph = [];
    while (index < lines.length && lines[index].trim() && !/^(#{1,3}\s|```|\s*([-*]|\d+\.)\s+|\s*\|)/.test(lines[index])) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push(<p key={key}>{inline(paragraph.join(' '), key)}</p>);
  }

  return <div className="sl-prose">{blocks}</div>;
}
