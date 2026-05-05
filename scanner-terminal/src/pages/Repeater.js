import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import CodeEditorPanel from '../components/ui/CodeEditorPanel';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';

export default function Repeater({
  manualRequest,
  updateManualRequest,
  sendManualReplay,
  saveManualRequest,
  manualState,
  repeaterTabs,
  activeRepeaterTabId,
  selectRepeaterTab,
  createRepeaterTab,
  closeRepeaterTab,
  selectedExchange,
  onNavigate,
}) {
  return (
    <div className="page-fill">
      <PageHeader
        eyebrow="Manual"
        title="Repeater"
        description="Edit, replay, and compare HTTP requests."
        actions={(
          <>
            <Button variant="secondary" onClick={() => onNavigate('intruder')}>Send to Intruder</Button>
            <Button variant="secondary" onClick={saveManualRequest} disabled={manualState === 'saving'}>{manualState === 'saving' ? 'Saving' : 'Save'}</Button>
            <Button onClick={sendManualReplay} disabled={manualState === 'sending'}>{manualState === 'sending' ? 'Sending' : 'Send'}</Button>
          </>
        )}
      />
      <div className="repeater-layout">
        <Card title="Request" eyebrow="Repeater">
          <div className="tab-strip">
            {repeaterTabs.map((tab) => (
              <button className={tab.tabId === activeRepeaterTabId ? 'active' : ''} key={tab.tabId} onClick={() => selectRepeaterTab(tab.tabId)}>
                {tab.title}
                {repeaterTabs.length > 1 && (
                  <span
                    aria-hidden="true"
                    onClick={(event) => { event.stopPropagation(); closeRepeaterTab(tab.tabId); }}
                  >
                    x
                  </span>
                )}
              </button>
            ))}
            <Button variant="ghost" onClick={createRepeaterTab}>New</Button>
          </div>
          <ManualRequestFields request={manualRequest} updateRequest={updateManualRequest} />
        </Card>
        <Card title="Response" eyebrow="Inspector">
          <RequestResponseViewer exchange={selectedExchange} />
        </Card>
      </div>
    </div>
  );
}

export function ManualRequestFields({ request, updateRequest }) {
  return (
    <div className="manual-request-fields">
      <div className="request-line">
        <select value={request.method} onChange={(event) => updateRequest('method', event.target.value)}>
          {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map((method) => <option key={method}>{method}</option>)}
        </select>
        <input value={request.url} onChange={(event) => updateRequest('url', event.target.value)} />
      </div>
      <div className="form-grid">
        <label className="field"><span>Scan ID</span><input value={request.scanId} onChange={(event) => updateRequest('scanId', event.target.value)} /></label>
        <label className="field"><span>Timeout</span><input value={request.timeout} onChange={(event) => updateRequest('timeout', event.target.value)} /></label>
        <label className="field"><span>Safety</span><select value={request.safetyMode} onChange={(event) => updateRequest('safetyMode', event.target.value)}><option>safe</option><option>intrusive</option><option>lab</option></select></label>
        <label className="check-row"><input type="checkbox" checked={request.allowStateChange} onChange={(event) => updateRequest('allowStateChange', event.target.checked)} /><span>Allow state change</span></label>
      </div>
      <CodeEditorPanel title="Headers" value={request.headers} onChange={(value) => updateRequest('headers', value)} minRows={8} />
      <CodeEditorPanel title="Body" value={request.body} onChange={(value) => updateRequest('body', value)} minRows={10} />
    </div>
  );
}
