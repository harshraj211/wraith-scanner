import React, { useMemo, useState } from 'react';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';
import { ComparerPanel } from './Comparer';

export default function Decoder(props) {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [activeFormat, setActiveFormat] = useState('url');
  const [history, setHistory] = useState([]);
  const source = output || input;
  const outputText = output;

  const inputMeta = useMemo(() => ({
    length: String(input || '').length,
    encoding: activeFormat.toUpperCase(),
  }), [activeFormat, input]);
  const outputMeta = useMemo(() => ({
    length: String(outputText || '').length,
    encoding: activeFormat === 'url' ? 'UTF-8' : activeFormat.toUpperCase(),
  }), [activeFormat, outputText]);

  const runTransform = (type) => {
    const result = safeTransform(source, type);
    setOutput(result);
    setActiveFormat(type.split('-')[0] || type);
    setHistory((current) => [
      { id: `${Date.now()}-${type}`, type, input: source, output: result, timestamp: new Date().toLocaleTimeString() },
      ...current,
    ].slice(0, 5));
  };

  return (
    <div className="page-stack lab-page decoder-page decoder-comparer-page">
      <section className="dc-panel decoder-panel">
        <header className="dc-section-head">
          <div>
            <h1>Decoder</h1>
            <p>Transform and decode data across multiple formats.</p>
          </div>
          <div className="dc-actions">
            <button type="button" onClick={() => setInput('')}>Clear</button>
            <button type="button" onClick={() => navigator.clipboard?.writeText(outputText)}>Copy</button>
            <button type="button" onClick={() => downloadText(outputText)}>Download</button>
          </div>
        </header>

        <div className="decoder-workbench">
          <CodePane
            title="Input"
            value={input}
            onChange={(value) => {
              setInput(value);
              setOutput('');
            }}
            meta={inputMeta}
          />

          <div className="transform-rack">
            <h2>Transform</h2>
            <div className="format-tabs">
              <button className={activeFormat === 'url' ? 'active' : ''} type="button" onClick={() => runTransform('url-decode')}>URL</button>
              <button className={activeFormat === 'base64' ? 'active' : ''} type="button" onClick={() => runTransform('base64-decode')}>Base64</button>
              <button className={activeFormat === 'html' ? 'active' : ''} type="button" onClick={() => runTransform('html-decode')}>HTML</button>
              <button className={activeFormat === 'jwt' ? 'active' : ''} type="button" onClick={() => runTransform('jwt-decode')}>JWT</button>
              <button className={activeFormat === 'hash' ? 'active' : ''} type="button" onClick={() => runTransform('json-pretty')}>Hash</button>
            </div>
            <div className="transform-actions">
              <Button variant="secondary" onClick={() => runTransform('url-decode')}>URL Decode</Button>
              <Button variant="secondary" onClick={() => runTransform('url-encode')}>URL Encode</Button>
              <Button variant="secondary" onClick={() => runTransform('base64-decode')}>Base64 Decode</Button>
              <Button variant="secondary" onClick={() => runTransform('base64-encode')}>Base64 Encode</Button>
              <Button variant="secondary" onClick={() => runTransform('json-pretty')}>Pretty JSON</Button>
              <Button variant="secondary" onClick={() => runTransform('jwt-decode')}>JWT Decode</Button>
            </div>
            <label className="field">
              <span>Encoding</span>
              <select value={outputMeta.encoding} onChange={() => {}}>
                <option>UTF-8</option>
                <option>ASCII</option>
              </select>
            </label>
            <label className="check-row"><input type="checkbox" defaultChecked /><span>Decode all levels</span></label>
            <label className="check-row"><input type="checkbox" defaultChecked /><span>Convert + to space</span></label>
            <label className="check-row"><input type="checkbox" /><span>Normalize Unicode</span></label>
            <Button onClick={() => runTransform('url-decode')}>
              <span className="material-symbols-outlined">play_arrow</span>
              Decode
            </Button>
            <p>Decodes percent-encoded characters in a URL string.</p>
          </div>

          <CodePane title="Output" value={outputText} readOnly meta={outputMeta} decoded={Boolean(outputText)} />

          <aside className="decoder-history">
            <h2>History</h2>
            <input placeholder="Search history..." readOnly />
            {history.length ? (
              history.map((item) => (
                <button type="button" key={item.id} onClick={() => {
                  setInput(item.input);
                  setOutput(item.output);
                }}>
                  <strong>{truncate(item.output || item.input, 34)}</strong>
                  <span>{item.type} - {item.timestamp}</span>
                </button>
              ))
            ) : (
              <EmptyState
                icon="history"
                title="No decode history"
                body="Run a transform to populate local history."
              />
            )}
            <button type="button" className="danger-link" onClick={() => setHistory([])}>Clear history</button>
          </aside>
        </div>
      </section>

      <ComparerPanel {...props} compact />
    </div>
  );
}

function CodePane({ title, value, onChange, readOnly = false, meta, decoded = false }) {
  return (
    <label className="dc-code-pane">
      <span>{title}</span>
      <textarea
        value={value || ''}
        onChange={(event) => onChange?.(event.target.value)}
        readOnly={readOnly}
        spellCheck={false}
      />
      <em>
        Length: {meta.length} chars
        <b>Encoding: {meta.encoding}</b>
        {decoded && <strong>Decoded</strong>}
      </em>
    </label>
  );
}

function safeTransform(value, type) {
  try {
    const source = String(value || '');
    if (type === 'url-decode') return decodeURIComponent(source).replace(/\+/g, ' ');
    if (type === 'url-encode') return encodeURIComponent(source);
    if (type === 'base64-decode') return atob(source.trim());
    if (type === 'base64-encode') return btoa(source);
    if (type === 'html-decode') {
      const textarea = document.createElement('textarea');
      textarea.innerHTML = source;
      return textarea.value;
    }
    if (type === 'json-pretty') return JSON.stringify(JSON.parse(source), null, 2);
    if (type === 'jwt-decode') {
      const parts = source.trim().split('.');
      if (parts.length < 2) throw new Error('JWT must have at least header and payload');
      const decodePart = (part) => JSON.stringify(JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
      return `Header\n${decodePart(parts[0])}\n\nPayload\n${decodePart(parts[1])}`;
    }
  } catch (error) {
    return `Decode error: ${error.message}`;
  }
  return String(value || '');
}

function truncate(value, length) {
  const text = String(value || '');
  return text.length > length ? `${text.slice(0, length)}...` : text;
}

function downloadText(value) {
  const blob = new Blob([value || ''], { type: 'text/plain' });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = 'wraith-decoder-output.txt';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(href);
}
