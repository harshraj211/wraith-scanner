import React, { useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';

function getStoredValue(key, fallback) {
  if (typeof window === 'undefined') return fallback;
  return window.localStorage.getItem(key) || fallback;
}

export default function Settings({ apiUrl }) {
  const [apiUrlDraft, setApiUrlDraft] = useState(() => getStoredValue('wraith.apiUrl', apiUrl || 'http://127.0.0.1:5001'));
  const [apiKeyDraft, setApiKeyDraft] = useState(() => getStoredValue('wraith.apiKey', ''));
  const [defaultSafetyMode, setDefaultSafetyMode] = useState(() => getStoredValue('wraith.defaultSafetyMode', 'safe'));
  const [confirmDangerousActions, setConfirmDangerousActions] = useState(() => getStoredValue('wraith.confirmDangerousActions', 'true') !== 'false');
  const [saveState, setSaveState] = useState('idle');

  const saveSettings = () => {
    window.localStorage.setItem('wraith.apiUrl', apiUrlDraft.trim() || 'http://127.0.0.1:5001');
    window.localStorage.setItem('wraith.apiKey', apiKeyDraft.trim());
    window.localStorage.setItem('wraith.defaultSafetyMode', defaultSafetyMode);
    window.localStorage.setItem('wraith.confirmDangerousActions', String(confirmDangerousActions));
    setSaveState('saved');
    window.setTimeout(() => setSaveState('idle'), 1800);
  };

  return (
    <div className="page-stack lab-page settings-page">
      <PageHeader
        eyebrow="Settings"
        title="Settings"
        description="Local workbench configuration and safety defaults."
        actions={<Button onClick={saveSettings}>{saveState === 'saved' ? 'Saved' : 'Save Settings'}</Button>}
      />
      <div className="settings-grid">
        <Card title="Safety Defaults" eyebrow="Policy">
          <label className="field">
            <span>Default Safety Mode</span>
            <select value={defaultSafetyMode} onChange={(event) => setDefaultSafetyMode(event.target.value)}>
              <option value="safe">safe</option>
              <option value="intrusive">intrusive</option>
              <option value="lab">lab</option>
            </select>
            <em className="field-hint">New automated scan forms use this default after reload.</em>
          </label>
          <label className="check-row">
            <input
              type="checkbox"
              checked={confirmDangerousActions}
              onChange={(event) => setConfirmDangerousActions(event.target.checked)}
            />
            <span>Confirm installs, template updates, proxy stops, and CA generation.</span>
          </label>
        </Card>
        <Card title="Backend" eyebrow="API">
          <label className="field">
            <span>API URL</span>
            <input
              value={apiUrlDraft}
              onChange={(event) => setApiUrlDraft(event.target.value)}
              placeholder="http://127.0.0.1:5001"
            />
            <em className="field-hint">Saved API URL is used the next time the frontend loads.</em>
          </label>
          <label className="field">
            <span>API Key</span>
            <input
              value={apiKeyDraft}
              onChange={(event) => setApiKeyDraft(event.target.value)}
              placeholder="wraith_sec_key_123"
            />
            <em className="field-hint">Stored locally and sent as `X-API-KEY` for protected endpoints.</em>
          </label>
          <div className="summary-list">
            <div><span>Current session</span><strong>{apiUrl}</strong></div>
            <div><span>Corpus</span><strong>SQLite</strong></div>
          </div>
        </Card>
      </div>
    </div>
  );
}
