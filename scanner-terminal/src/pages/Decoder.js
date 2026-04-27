import React, { useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import CodeEditorPanel from '../components/ui/CodeEditorPanel';

export default function Decoder() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const runTransform = (type) => {
    try {
      const source = output || input;
      if (type === 'url-decode') setOutput(decodeURIComponent(source));
      if (type === 'url-encode') setOutput(encodeURIComponent(source));
      if (type === 'base64-decode') setOutput(atob(source.trim()));
      if (type === 'base64-encode') setOutput(btoa(source));
      if (type === 'json-pretty') setOutput(JSON.stringify(JSON.parse(source), null, 2));
      if (type === 'jwt-decode') {
        const parts = source.trim().split('.');
        if (parts.length < 2) throw new Error('JWT must have at least header and payload');
        const decodePart = (part) => JSON.stringify(JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
        setOutput(`Header\n${decodePart(parts[0])}\n\nPayload\n${decodePart(parts[1])}`);
      }
    } catch (error) {
      setOutput(`Decode error: ${error.message}`);
    }
  };
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Manual" title="Decoder" description="Chain common AppSec encoders and decoders." />
      <Card title="Encode and Decode" eyebrow="Utility">
        <div className="decoder-grid">
          <CodeEditorPanel title="Input" value={input} onChange={(value) => { setInput(value); setOutput(''); }} />
          <div className="decoder-actions">
            <Button variant="secondary" onClick={() => runTransform('url-decode')}>URL decode</Button>
            <Button variant="secondary" onClick={() => runTransform('url-encode')}>URL encode</Button>
            <Button variant="secondary" onClick={() => runTransform('base64-decode')}>Base64 decode</Button>
            <Button variant="secondary" onClick={() => runTransform('base64-encode')}>Base64 encode</Button>
            <Button variant="secondary" onClick={() => runTransform('json-pretty')}>Pretty JSON</Button>
            <Button variant="secondary" onClick={() => runTransform('jwt-decode')}>Decode JWT</Button>
          </div>
          <CodeEditorPanel title="Output" value={output} readOnly />
        </div>
      </Card>
    </div>
  );
}
