import React from 'react';
import Markdown from '../components/common/Markdown.jsx';
import spec from '../../docs/spec/instruction-security-policy.md?raw';

export default function SpecPage() {
  return (
    <div className="sl-wrap" style={{ padding: '48px 24px 72px' }}>
      <article aria-label="Instruction Security Policy specification">
        <Markdown source={spec} />
      </article>
    </div>
  );
}
