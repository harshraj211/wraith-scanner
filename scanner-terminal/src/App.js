import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import io from 'socket.io-client';
import axios from 'axios';
import 'xterm/css/xterm.css';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:5001';

const ESC = String.fromCharCode(27);
const RESET = `${ESC}[0m`;
const c = (code, text) => `${ESC}[${code}m${text}${RESET}`;

const initialForm = {
  targetUrl: 'http://127.0.0.1:5000',
  depth: '3',
  timeout: '10',
  safetyMode: 'safe',
  authType: 'anonymous',
  authRole: 'anonymous',
  bearerToken: '',
  headers: '',
  cookies: '',
  storageStatePath: '',
  healthUrl: '',
  healthText: '',
  openapiImports: '',
  postmanImports: '',
  harImports: '',
  graphqlImports: '',
  graphqlEndpoint: '',
  sequenceWorkflows: '',
};

const initialManualRequest = {
  scanId: '',
  method: 'GET',
  url: 'http://127.0.0.1:5000/',
  headers: 'User-Agent: Wraith-Manual',
  body: '',
  timeout: '10',
  safetyMode: 'safe',
  allowStateChange: false,
};

function initialViewFromLocation() {
  const hash = String(window.location.hash || '').toLowerCase();
  if (['#scan-setup', '#result-dashboard', '#traffic-corpus', '#terminal', '#automated'].includes(hash)) {
    return 'automated';
  }
  if (['#proxy-history', '#replay', '#response', '#manual'].includes(hash)) {
    return 'manual';
  }
  if (hash === '#start' || hash === '#mode') return 'mode';
  return 'home';
}

function App() {
  const terminalRef = useRef(null);
  const fitAddonRef = useRef(null);
  const termRef = useRef(null);
  const [terminal, setTerminal] = useState(null);
  const [view, setViewState] = useState(initialViewFromLocation);
  const [socketState, setSocketState] = useState('idle');
  const [form, setForm] = useState(initialForm);
  const [manualRequest, setManualRequest] = useState(initialManualRequest);
  const [manualState, setManualState] = useState('idle');
  const [launchState, setLaunchState] = useState('idle');
  const [latestScanId, setLatestScanId] = useState('');
  const [scanStatus, setScanStatus] = useState(null);
  const [progressEvents, setProgressEvents] = useState([]);
  const [corpusFilters, setCorpusFilters] = useState({
    method: '',
    source: '',
    statusCode: '',
    pathContains: '',
  });
  const [corpusRequests, setCorpusRequests] = useState([]);
  const [selectedExchange, setSelectedExchange] = useState(null);
  const [corpusState, setCorpusState] = useState('idle');

  const addProgress = useCallback((event) => {
    setProgressEvents((current) => [
      {
        scan_id: event.scan_id || '',
        type: event.type || 'info',
        message: event.message || '',
        timestamp: event.timestamp || new Date().toISOString(),
      },
      ...current,
    ].slice(0, 80));
  }, []);

  const scanPayload = useMemo(() => buildScanPayload(form), [form]);
  const dashboard = useMemo(
    () => buildDashboard(scanStatus, corpusRequests, progressEvents, scanPayload),
    [scanPayload, scanStatus, corpusRequests, progressEvents],
  );

  const setView = useCallback((nextView) => {
    setViewState(nextView);
    const hashByView = {
      home: '',
      mode: '#start',
      automated: '#scan-setup',
      manual: '#replay',
    };
    const nextHash = hashByView[nextView] || '';
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, '', `${window.location.pathname}${nextHash}`);
    }
  }, []);

  useEffect(() => {
    const syncHash = () => setViewState(initialViewFromLocation());
    window.addEventListener('hashchange', syncHash);
    return () => window.removeEventListener('hashchange', syncHash);
  }, []);

  useEffect(() => {
    if (!terminalRef.current) return undefined;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: '"Fira Code", "Cascadia Code", "JetBrains Mono", Consolas, monospace',
      theme: {
        background: '#0f1217',
        foreground: '#d9e0ea',
        cursor: '#7cc7ff',
        cursorAccent: '#0f1217',
        black: '#0f1217',
        red: '#ff6b6b',
        green: '#50c878',
        yellow: '#f7c948',
        blue: '#64a6ff',
        magenta: '#c084fc',
        cyan: '#45d3c6',
        white: '#d9e0ea',
        brightBlack: '#687385',
        brightRed: '#ff8f86',
        brightGreen: '#7dde92',
        brightYellow: '#ffd166',
        brightBlue: '#8ec5ff',
        brightMagenta: '#d7b2ff',
        brightCyan: '#79eee4',
        brightWhite: '#ffffff',
      },
      lineHeight: 1.3,
      scrollback: 5000,
    });
    ensureTerminalApi(term);

    const fitAddon = new FitAddon();
    fitAddonRef.current = fitAddon;
    if (typeof term.loadAddon === 'function') {
      term.loadAddon(fitAddon);
      term.loadAddon(new WebLinksAddon());
    }
    term.open(terminalRef.current);
    if (typeof fitAddon.fit === 'function') fitAddon.fit();
    termRef.current = term;
    printBanner(term);
    printPrompt(term);
    setTerminal(term);
    setSocketState('connecting');

    const ws = io(API_URL) || { on: () => {}, disconnect: () => {} };
    ws.on('connect', () => {
      setSocketState('connected');
      term.writeln(c('38;5;108', '[ws] connected to api server'));
    });
    ws.on('scan_progress', (event) => {
      addProgress(event);
      term.writeln(formatProgressLine(event.message, event.type));
    });
    ws.on('disconnect', () => {
      setSocketState('disconnected');
      term.writeln(c('38;5;203', '[ws] connection lost'));
    });
    ws.on('connect_error', () => {
      setSocketState('error');
      term.writeln(c('38;5;203', `[ws] unable to reach api server at ${API_URL}`));
    });

    const handleResize = () => {
      if (typeof fitAddon.fit === 'function') fitAddon.fit();
    };
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      ws.disconnect();
      term.dispose();
      termRef.current = null;
      setTerminal(null);
      setSocketState('idle');
    };
  }, [addProgress, view]);

  useEffect(() => {
    if (!terminal) return undefined;
    let line = '';

    const disposable = terminal.onData(async (data) => {
      const code = data.charCodeAt(0);
      if (code === 13) {
        terminal.writeln('');
        const cmd = line.trim();
        if (cmd) {
          await executeCommand(cmd, terminal, {
            setLatestScanId,
            setScanStatus,
            addProgress,
          });
        }
        line = '';
        printPrompt(terminal);
      } else if (code === 127) {
        if (line.length > 0) {
          line = line.slice(0, -1);
          terminal.write('\b \b');
        }
      } else if (code >= 32) {
        line += data;
        terminal.write(data);
      }
    });

    return () => disposable.dispose();
  }, [addProgress, terminal]);

  const updateForm = (name, value) => {
    setForm((current) => ({ ...current, [name]: value }));
  };

  const updateManualRequest = (name, value) => {
    setManualRequest((current) => ({ ...current, [name]: value }));
  };

  const submitScan = async (event) => {
    if (event?.preventDefault) event.preventDefault();
    if (!scanPayload.url) return;
    setView('automated');
    setLaunchState('running');
    setScanStatus(null);
    try {
      const response = await axios.post(`${API_URL}/api/scan`, scanPayload);
      const scanId = response.data.scan_id;
      setLatestScanId(scanId);
      setManualRequest((current) => ({ ...current, scanId }));
      addProgress({
        scan_id: scanId,
        type: 'success',
        message: `Scan started: ${scanId}`,
      });
      if (termRef.current) {
        termRef.current.writeln(c('38;5;108', `[setup] scan started: ${scanId}`));
      }
      setLaunchState('started');
    } catch (error) {
      setLaunchState('error');
      addProgress({
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const refreshStatus = async (scanId = latestScanId) => {
    if (!scanId) return;
    try {
      const response = await axios.get(`${API_URL}/api/scan/${scanId}`);
      setScanStatus(response.data);
    } catch (error) {
      addProgress({
        scan_id: scanId,
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const loadCorpus = async (scanIdOverride) => {
    const scanId = scanIdOverride || latestScanId || manualRequest.scanId;
    if (!scanId) return;
    setCorpusState('loading');
    try {
      const params = {};
      if (corpusFilters.method) params.method = corpusFilters.method;
      if (corpusFilters.source) params.source = corpusFilters.source;
      if (corpusFilters.statusCode) params.status_code = corpusFilters.statusCode;
      if (corpusFilters.pathContains) params.path_contains = corpusFilters.pathContains;
      const response = await axios.get(`${API_URL}/api/corpus/${scanId}/requests`, { params });
      const requests = response.data.requests || [];
      setCorpusRequests(requests);
      setCorpusState('loaded');
      if (requests.length > 0) {
        loadExchange(requests[0].request_id);
      } else {
        setSelectedExchange(null);
      }
    } catch (error) {
      setCorpusState('error');
      addProgress({
        scan_id: scanId,
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const loadExchange = async (requestId) => {
    if (!requestId) return;
    try {
      const response = await axios.get(`${API_URL}/api/corpus/request/${requestId}`);
      setSelectedExchange(response.data);
    } catch (error) {
      addProgress({
        scan_id: latestScanId,
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const sendManualReplay = async () => {
    if (!manualRequest.url.trim()) return;
    setManualState('sending');
    try {
      const response = await axios.post(`${API_URL}/api/manual/replay`, {
        scan_id: manualRequest.scanId || latestScanId,
        method: manualRequest.method,
        url: manualRequest.url.trim(),
        headers: parseKeyValueLines(manualRequest.headers),
        body: manualRequest.body,
        timeout: parseInt(manualRequest.timeout, 10) || 10,
        safety_mode: manualRequest.safetyMode,
        allow_state_change: manualRequest.allowStateChange,
        auth_role: 'manual',
      });
      const scanId = response.data.scan_id;
      setManualState('sent');
      setLatestScanId(scanId);
      setManualRequest((current) => ({ ...current, scanId }));
      setSelectedExchange({
        request: response.data.request,
        response: response.data.response,
      });
      await loadCorpus(scanId);
      addProgress({
        scan_id: scanId,
        type: 'success',
        message: `Manual replay captured: ${response.data.request?.method || ''} ${response.data.request?.url || ''}`,
      });
    } catch (error) {
      setManualState('error');
      addProgress({
        scan_id: manualRequest.scanId || latestScanId,
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const updateCorpusFilter = (name, value) => {
    setCorpusFilters((current) => ({ ...current, [name]: value }));
  };

  const importCount = countImports(scanPayload.imports);
  const workflowCount = (scanPayload.sequence_workflows || []).length;

  return (
    <div className={`App app-${view}`}>
      <SiteHeader view={view} setView={setView} socketState={socketState} />
      {view === 'home' && <LandingPage setView={setView} />}
      {view === 'mode' && <ModeSelectPage setView={setView} />}
      {view === 'automated' && (
        <AutomatedPage
          form={form}
          updateForm={updateForm}
          submitScan={submitScan}
          launchState={launchState}
          latestScanId={latestScanId}
          scanStatus={scanStatus}
          dashboard={dashboard}
          progressEvents={progressEvents}
          refreshStatus={refreshStatus}
          loadCorpus={loadCorpus}
          corpusFilters={corpusFilters}
          updateCorpusFilter={updateCorpusFilter}
          corpusRequests={corpusRequests}
          selectedExchange={selectedExchange}
          loadExchange={loadExchange}
          corpusState={corpusState}
          importCount={importCount}
          workflowCount={workflowCount}
          terminalRef={terminalRef}
        />
      )}
      {view === 'manual' && (
        <ManualPage
          manualRequest={manualRequest}
          updateManualRequest={updateManualRequest}
          sendManualReplay={sendManualReplay}
          manualState={manualState}
          latestScanId={latestScanId}
          loadCorpus={loadCorpus}
          corpusFilters={corpusFilters}
          updateCorpusFilter={updateCorpusFilter}
          corpusRequests={corpusRequests}
          selectedExchange={selectedExchange}
          loadExchange={loadExchange}
          corpusState={corpusState}
          terminalRef={terminalRef}
        />
      )}
    </div>
  );
}

function SiteHeader({ view, setView, socketState }) {
  const inWorkbench = view === 'automated' || view === 'manual';
  return (
    <header className={`site-header ${inWorkbench ? 'site-header-dark' : ''}`}>
      <button className="brand-button" onClick={() => setView('home')}>
        <span className="brand-mark">W</span>
        <span>Wraith</span>
      </button>
      <nav className="site-nav" aria-label="Primary">
        <button onClick={() => setView('home')}>Home</button>
        <button onClick={() => setView('automated')}>Automated</button>
        <button onClick={() => setView('manual')}>Manual</button>
      </nav>
      <div className="header-actions">
        {inWorkbench && <span className={`socket-pill socket-${socketState}`}>{socketState}</span>}
        <button className="primary-button" onClick={() => setView('mode')}>Start Scan</button>
      </div>
    </header>
  );
}

function LandingPage({ setView }) {
  const featureTiles = [
    ['DAST', 'SQLi, XSS, SSRF, XXE, SSTI, IDOR, redirects, CSRF, headers, GraphQL, WebSockets'],
    ['SAST', 'Semgrep findings, Python and JavaScript taint traces, secrets, dependency CVEs'],
    ['SPA', 'Playwright crawling, browser storage snapshots, route extraction, state mutation'],
    ['Evidence', 'SQLite corpus, stable finding IDs, redaction, JSON/PDF exports, OOB correlation'],
  ];

  return (
    <main className="marketing-page">
      <section className="hero-section">
        <HeroDashboard />
        <div className="hero-copy">
          <span className="eyebrow">VA + Proof scanner</span>
          <h1>Wraith v4</h1>
          <p>
            Modern web vulnerability assessment for SPAs, APIs, and source/runtime correlation.
            Wraith discovers attack surface, stores defensible evidence, and prepares findings for safe proof.
          </p>
          <div className="hero-actions">
            <button className="primary-button large" onClick={() => setView('mode')}>Start Scan</button>
            <button className="secondary-button large" onClick={() => setView('manual')}>Manual Workbench</button>
          </div>
        </div>
      </section>

      <section className="metric-strip" aria-label="Wraith coverage">
        <Metric label="DAST modules" value="18" />
        <Metric label="API importers" value="4" />
        <Metric label="Proof modes" value="3" />
        <Metric label="Evidence store" value="SQLite" />
        <Metric label="Exports" value="JSON PDF" />
      </section>

      <section className="feature-band">
        <div className="band-heading">
          <span className="eyebrow">Detection to evidence</span>
          <h2>Built for scans a professional can defend</h2>
        </div>
        <div className="feature-grid">
          {featureTiles.map(([title, body]) => (
            <article className="feature-tile" key={title}>
              <strong>{title}</strong>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}

function HeroDashboard() {
  return (
    <div className="hero-dashboard" aria-hidden="true">
      <div className="mock-browser">
        <div className="mock-topbar">
          <span />
          <span />
          <span />
        </div>
        <div className="mock-shell">
          <div className="mock-sidebar" />
          <div className="mock-content">
            <div className="mock-kpis">
              <i />
              <i />
              <i />
              <i />
            </div>
            <div className="mock-grid">
              <div className="mock-donut" />
              <div className="mock-matrix">
                {Array.from({ length: 24 }).map((_, index) => <span key={index} />)}
              </div>
              <div className="mock-donut mock-donut-alt" />
            </div>
            <div className="mock-chart">
              <span />
              <span />
              <span />
              <span />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ModeSelectPage({ setView }) {
  return (
    <main className="mode-page">
      <section className="mode-hero">
        <span className="eyebrow">Choose workflow</span>
        <h1>Start Wraith</h1>
      </section>
      <section className="mode-grid">
        <article className="mode-card">
          <span className="mode-label">Automated</span>
          <h2>Automated Scan</h2>
          <p>Run authenticated DAST, API imports, sequence workflows, SAST correlation, and visual reporting from one page.</p>
          <button className="primary-button" onClick={() => setView('automated')}>Open Automated</button>
        </article>
        <article className="mode-card">
          <span className="mode-label">Manual</span>
          <h2>Manual Scan</h2>
          <p>Inspect captured traffic, replay requests, edit payloads, compare responses, and preserve evidence in the corpus.</p>
          <button className="secondary-button" onClick={() => setView('manual')}>Open Manual</button>
        </article>
      </section>
    </main>
  );
}

function AutomatedPage({
  form,
  updateForm,
  submitScan,
  launchState,
  latestScanId,
  scanStatus,
  dashboard,
  progressEvents,
  refreshStatus,
  loadCorpus,
  corpusFilters,
  updateCorpusFilter,
  corpusRequests,
  selectedExchange,
  loadExchange,
  corpusState,
  importCount,
  workflowCount,
  terminalRef,
}) {
  return (
    <div className="app-shell enterprise-shell">
      <EnterpriseRail
        mode="Automated"
        activeTitle={scanPayloadTitle(form.targetUrl)}
        scanId={latestScanId}
        status={scanStatus?.status || launchState}
        requests={corpusRequests.length}
      />
      <main className="enterprise-workspace">
        <WorkspaceHeader
          title={scanPayloadTitle(form.targetUrl)}
          subtitle="Automated scan workspace"
          scanId={latestScanId}
          onRefresh={() => refreshStatus()}
          onScan={submitScan}
          scanDisabled={launchState === 'running'}
          scanLabel={launchState === 'running' ? 'Starting' : 'Scan again'}
        />
        <ScanMetaBar
          status={scanStatus?.status || (latestScanId ? launchState : 'Not started')}
          startTime={scanStatus?.start_time || 'Pending'}
          endTime={scanStatus?.end_time || 'Pending'}
          duration={scanStatus?.duration || 'Pending'}
        />
        <WorkspaceTabs
          tabs={[
            ['Overview', '#result-dashboard'],
            ['Issues', '#result-dashboard'],
            ['Scanned URLs', '#traffic-corpus'],
            ['Scan details', '#scan-setup'],
            ['Reporting & logs', '#terminal'],
          ]}
        />
        <ReportActions scanId={latestScanId} />

        <div className="automated-grid">
          <section id="scan-setup" className="setup-panel">
            <div className="section-heading">
              <div>
                <span className="eyebrow">Automated mode</span>
                <h1>Scan Setup</h1>
              </div>
              <button className="primary-button" onClick={submitScan} disabled={launchState === 'running'}>
                {launchState === 'running' ? 'Starting' : 'Start Scan'}
              </button>
            </div>
            <ScanSetupForm form={form} updateForm={updateForm} submitScan={submitScan} />
          </section>

          <section id="result-dashboard" className="dashboard-panel">
            <div className="section-heading compact">
              <div>
                <span className="eyebrow">Visual results</span>
                <h2>Risk Dashboard</h2>
              </div>
              <button className="secondary-button" onClick={() => refreshStatus()} disabled={!latestScanId}>Refresh</button>
            </div>
            <ResultDashboard dashboard={dashboard} scanId={latestScanId} status={scanStatus} launchState={launchState} />
          </section>

          <section className="progress-panel">
            <div className="section-heading compact">
              <div>
                <span className="eyebrow">Run state</span>
                <h2>Progress</h2>
              </div>
            </div>
            <StatusSummary scanId={latestScanId} status={scanStatus} launchState={launchState} />
            <ProgressEvents events={progressEvents} />
          </section>

          <section id="traffic-corpus" className="corpus-panel">
            <CorpusHeader
              latestScanId={latestScanId}
              loadCorpus={loadCorpus}
              corpusState={corpusState}
              corpusFilters={corpusFilters}
              updateCorpusFilter={updateCorpusFilter}
            />
            <CorpusViewer requests={corpusRequests} selectedExchange={selectedExchange} onSelect={loadExchange} />
          </section>

          <TerminalPanel terminalRef={terminalRef} />
        </div>
      </main>
    </div>
  );
}

function ManualPage({
  manualRequest,
  updateManualRequest,
  sendManualReplay,
  manualState,
  latestScanId,
  loadCorpus,
  corpusFilters,
  updateCorpusFilter,
  corpusRequests,
  selectedExchange,
  loadExchange,
  corpusState,
  terminalRef,
}) {
  return (
    <div className="app-shell manual-shell enterprise-shell">
      <EnterpriseRail
        mode="Manual"
        activeTitle="Manual testing"
        scanId={manualRequest.scanId || latestScanId}
        status={manualState}
        requests={corpusRequests.length}
      />

      <main className="enterprise-workspace manual-workspace">
        <WorkspaceHeader
          title="Manual testing"
          subtitle="Proxy-style request history, repeater, response inspector"
          scanId={manualRequest.scanId || latestScanId}
          onRefresh={() => loadCorpus(manualRequest.scanId || latestScanId)}
          onScan={sendManualReplay}
          scanDisabled={manualState === 'sending'}
          scanLabel={manualState === 'sending' ? 'Sending' : 'Send request'}
        />
        <ScanMetaBar
          status={manualState}
          startTime="Manual"
          endTime="Operator controlled"
          duration={`${corpusRequests.length} captured`}
        />
        <WorkspaceTabs
          tabs={[
            ['Proxy history', '#proxy-history'],
            ['Repeater', '#replay'],
            ['Response inspector', '#response'],
            ['Reporting & logs', '#terminal'],
          ]}
        />
        <ReportActions scanId={manualRequest.scanId || latestScanId} />

        <div className="manual-grid">
          <section id="proxy-history" className="history-panel">
            <CorpusHeader
              latestScanId={manualRequest.scanId || latestScanId}
              loadCorpus={loadCorpus}
              corpusState={corpusState}
              corpusFilters={corpusFilters}
              updateCorpusFilter={updateCorpusFilter}
              compact
            />
            <RequestHistory requests={corpusRequests} selectedExchange={selectedExchange} onSelect={loadExchange} />
          </section>

          <section id="replay" className="replay-panel">
            <div className="section-heading compact">
              <div>
                <span className="eyebrow">Repeater</span>
                <h2>Request</h2>
              </div>
              <button className="primary-button" onClick={sendManualReplay} disabled={manualState === 'sending'}>
                {manualState === 'sending' ? 'Sending' : 'Send'}
              </button>
            </div>
            <ManualRequestEditor request={manualRequest} updateRequest={updateManualRequest} />
          </section>

          <section id="response" className="response-panel">
            <div className="section-heading compact">
              <div>
                <span className="eyebrow">Inspector</span>
                <h2>Response</h2>
              </div>
            </div>
            <ExchangeDetail exchange={selectedExchange} />
          </section>

          <TerminalPanel terminalRef={terminalRef} />
        </div>
      </main>
    </div>
  );
}

function EnterpriseRail({ mode, activeTitle, scanId, status, requests }) {
  const sampleScans = [
    ['Schuppe and Sons', scanId || 'latest', status || 'ready'],
    ['API staging', 'api-imports', 'queued'],
    ['SPA auth flow', 'spa-state', 'ready'],
    ['Manual session', 'manual', 'capturing'],
    ['Source review', 'sast', 'complete'],
  ];

  return (
    <aside className="app-rail enterprise-rail">
      <div className="rail-section rail-accent">
        <strong>{mode}</strong>
        <span>{activeTitle}</span>
      </div>
      <div className="rail-filter">
        <button>Filter by</button>
        <button>Most recent</button>
      </div>
      <div className="scan-list" aria-label={`${mode} scan list`}>
        {sampleScans.map(([name, id, state]) => (
          <a className={id === (scanId || 'latest') ? 'scan-list-row active' : 'scan-list-row'} href="#scan-setup" key={`${name}-${id}`}>
            <span>{name}</span>
            <strong>{state}</strong>
          </a>
        ))}
      </div>
      <div className="rail-metrics">
        <Metric label="Scan ID" value={scanId || 'none'} />
        <Metric label="Requests" value={requests} />
        <Metric label="Mode" value={mode} />
      </div>
    </aside>
  );
}

function WorkspaceHeader({ title, subtitle, scanId, onRefresh, onScan, scanDisabled, scanLabel }) {
  return (
    <section className="workspace-header">
      <div>
        <span className="workspace-back">Back</span>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      <div className="workspace-actions">
        <button className="secondary-button" onClick={onRefresh} disabled={!scanId}>Refresh</button>
        <button className="secondary-button" onClick={() => scanId && window.open(`${API_URL}/api/download-json/${scanId}`, '_blank')} disabled={!scanId}>JSON</button>
        <button className="primary-button" onClick={onScan} disabled={scanDisabled}>{scanLabel}</button>
      </div>
    </section>
  );
}

function ScanMetaBar({ status, startTime, endTime, duration }) {
  return (
    <section className="scan-meta-bar">
      <div>
        <span>Status</span>
        <strong>{status || 'Pending'}</strong>
      </div>
      <div>
        <span>Start time</span>
        <strong>{startTime || 'Pending'}</strong>
      </div>
      <div>
        <span>End time</span>
        <strong>{endTime || 'Pending'}</strong>
      </div>
      <div>
        <span>Duration</span>
        <strong>{duration || 'Pending'}</strong>
      </div>
    </section>
  );
}

function WorkspaceTabs({ tabs }) {
  return (
    <nav className="workspace-tabs" aria-label="Workspace sections">
      {tabs.map(([label, href], index) => (
        <a className={index === 0 ? 'active' : ''} href={href} key={label}>{label}</a>
      ))}
    </nav>
  );
}

function ReportActions({ scanId }) {
  return (
    <section className="report-strip">
      <span>Reporting & logs</span>
      <p>PDF and JSON reports are generated by the backend after scans complete.</p>
      <div>
        <button className="secondary-button" onClick={() => scanId && window.open(`${API_URL}/api/download/${scanId}`, '_blank')} disabled={!scanId}>Download PDF</button>
        <button className="secondary-button" onClick={() => scanId && window.open(`${API_URL}/api/download-json/${scanId}`, '_blank')} disabled={!scanId}>Download JSON</button>
      </div>
    </section>
  );
}

function ScanSetupForm({ form, updateForm, submitScan }) {
  return (
    <form className="scan-form" onSubmit={submitScan}>
      <fieldset>
        <legend>Target</legend>
        <label className="field wide">
          <span>Base URL</span>
          <input value={form.targetUrl} onChange={(e) => updateForm('targetUrl', e.target.value)} />
        </label>
        <label className="field">
          <span>Depth</span>
          <input type="number" min="1" value={form.depth} onChange={(e) => updateForm('depth', e.target.value)} />
        </label>
        <label className="field">
          <span>Timeout</span>
          <input type="number" min="1" value={form.timeout} onChange={(e) => updateForm('timeout', e.target.value)} />
        </label>
        <label className="field">
          <span>Safety</span>
          <select value={form.safetyMode} onChange={(e) => updateForm('safetyMode', e.target.value)}>
            <option value="safe">safe</option>
            <option value="intrusive">intrusive</option>
            <option value="lab">lab</option>
          </select>
        </label>
      </fieldset>

      <fieldset>
        <legend>Auth Profile</legend>
        <label className="field">
          <span>Type</span>
          <select value={form.authType} onChange={(e) => updateForm('authType', e.target.value)}>
            <option value="anonymous">anonymous</option>
            <option value="bearer">bearer</option>
            <option value="header">headers</option>
            <option value="cookie">cookies</option>
            <option value="playwright_storage">storage state</option>
            <option value="custom">custom</option>
          </select>
        </label>
        <label className="field">
          <span>Role</span>
          <input value={form.authRole} onChange={(e) => updateForm('authRole', e.target.value)} />
        </label>
        <label className="field wide">
          <span>Bearer token</span>
          <input type="password" value={form.bearerToken} onChange={(e) => updateForm('bearerToken', e.target.value)} />
        </label>
        <label className="field wide">
          <span>Headers</span>
          <textarea rows="3" value={form.headers} onChange={(e) => updateForm('headers', e.target.value)} placeholder="X-API-Key=..." />
        </label>
        <label className="field wide">
          <span>Cookies</span>
          <textarea rows="3" value={form.cookies} onChange={(e) => updateForm('cookies', e.target.value)} placeholder="sessionid=..." />
        </label>
        <label className="field wide">
          <span>Storage state path</span>
          <input value={form.storageStatePath} onChange={(e) => updateForm('storageStatePath', e.target.value)} />
        </label>
        <label className="field">
          <span>Health URL</span>
          <input value={form.healthUrl} onChange={(e) => updateForm('healthUrl', e.target.value)} />
        </label>
        <label className="field">
          <span>Expected text</span>
          <input value={form.healthText} onChange={(e) => updateForm('healthText', e.target.value)} />
        </label>
      </fieldset>

      <fieldset>
        <legend>API Imports</legend>
        <label className="field wide">
          <span>OpenAPI / Swagger</span>
          <textarea rows="2" value={form.openapiImports} onChange={(e) => updateForm('openapiImports', e.target.value)} placeholder="openapi.json or https://target/openapi.json" />
        </label>
        <label className="field wide">
          <span>Postman</span>
          <textarea rows="2" value={form.postmanImports} onChange={(e) => updateForm('postmanImports', e.target.value)} />
        </label>
        <label className="field wide">
          <span>HAR</span>
          <textarea rows="2" value={form.harImports} onChange={(e) => updateForm('harImports', e.target.value)} />
        </label>
        <label className="field wide">
          <span>GraphQL schema</span>
          <textarea rows="2" value={form.graphqlImports} onChange={(e) => updateForm('graphqlImports', e.target.value)} />
        </label>
        <label className="field wide">
          <span>GraphQL endpoint</span>
          <input value={form.graphqlEndpoint} onChange={(e) => updateForm('graphqlEndpoint', e.target.value)} />
        </label>
      </fieldset>

      <fieldset>
        <legend>Sequence Workflows</legend>
        <label className="field wide">
          <span>YAML / JSON paths</span>
          <textarea rows="3" value={form.sequenceWorkflows} onChange={(e) => updateForm('sequenceWorkflows', e.target.value)} placeholder="workflows/order-flow.yaml" />
        </label>
      </fieldset>
    </form>
  );
}

function ManualRequestEditor({ request, updateRequest }) {
  return (
    <form className="manual-form">
      <div className="request-line">
        <select value={request.method} onChange={(e) => updateRequest('method', e.target.value)}>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="PATCH">PATCH</option>
          <option value="DELETE">DELETE</option>
          <option value="HEAD">HEAD</option>
        </select>
        <input value={request.url} onChange={(e) => updateRequest('url', e.target.value)} />
      </div>
      <div className="manual-options">
        <label className="field">
          <span>Scan ID</span>
          <input value={request.scanId} onChange={(e) => updateRequest('scanId', e.target.value)} />
        </label>
        <label className="field">
          <span>Timeout</span>
          <input type="number" min="1" max="30" value={request.timeout} onChange={(e) => updateRequest('timeout', e.target.value)} />
        </label>
        <label className="field">
          <span>Safety</span>
          <select value={request.safetyMode} onChange={(e) => updateRequest('safetyMode', e.target.value)}>
            <option value="safe">safe</option>
            <option value="intrusive">intrusive</option>
            <option value="lab">lab</option>
          </select>
        </label>
        <label className="check-field">
          <input type="checkbox" checked={request.allowStateChange} onChange={(e) => updateRequest('allowStateChange', e.target.checked)} />
          <span>Allow state change</span>
        </label>
      </div>
      <label className="raw-field">
        <span>Headers</span>
        <textarea value={request.headers} onChange={(e) => updateRequest('headers', e.target.value)} spellCheck="false" />
      </label>
      <label className="raw-field">
        <span>Body</span>
        <textarea value={request.body} onChange={(e) => updateRequest('body', e.target.value)} spellCheck="false" />
      </label>
    </form>
  );
}

function ResultDashboard({ dashboard, scanId, status, launchState }) {
  return (
    <div className="result-dashboard">
      <div className="kpi-row">
        <KpiTile label="Total Findings" value={dashboard.totalFindings} tone="red" />
        <KpiTile label="Confirmed" value={dashboard.confirmedFindings} tone="green" />
        <KpiTile label="Requests" value={dashboard.requestCount} tone="blue" />
        <KpiTile label="Imports" value={dashboard.importCount} tone="gold" />
      </div>
      <div className="visual-grid">
        <section className="visual-panel">
          <div className="panel-title">
            <span>Severity Summary</span>
            <strong>{scanId || launchState || 'idle'}</strong>
          </div>
          <SeverityDonut counts={dashboard.severityCounts} />
        </section>
        <section className="visual-panel">
          <div className="panel-title">
            <span>Age Matrix</span>
            <strong>{status?.status || 'not started'}</strong>
          </div>
          <SeverityMatrix counts={dashboard.severityCounts} />
        </section>
        <section className="visual-panel">
          <div className="panel-title">
            <span>Attack Surface</span>
            <strong>{dashboard.categoryRows.length}</strong>
          </div>
          <CategoryBars rows={dashboard.categoryRows} />
        </section>
      </div>
      <section className="timeline-panel">
        <div className="panel-title">
          <span>Vulnerabilities Over Time</span>
          <strong>{dashboard.timeline.length}</strong>
        </div>
        <Timeline points={dashboard.timeline} />
      </section>
    </div>
  );
}

function StatusSummary({ scanId, status, launchState }) {
  const current = status?.status || (scanId ? launchState : 'idle');
  return (
    <div className="status-summary">
      <div>
        <span>Scan ID</span>
        <strong>{scanId || 'none'}</strong>
      </div>
      <div>
        <span>Status</span>
        <strong>{current}</strong>
      </div>
      <div>
        <span>Findings</span>
        <strong>{status?.total_vulnerabilities ?? 0}</strong>
      </div>
      <div>
        <span>Imports</span>
        <strong>{status?.api_imports ? countImports(status.api_imports) : 0}</strong>
      </div>
    </div>
  );
}

function ProgressEvents({ events }) {
  return (
    <div className="event-list" aria-live="polite">
      {events.length === 0 ? (
        <p className="empty-state">No scan events yet.</p>
      ) : events.map((event, index) => (
        <div className={`event-row event-${event.type}`} key={`${event.timestamp}-${index}`}>
          <span>{event.type}</span>
          <p>{event.message}</p>
        </div>
      ))}
    </div>
  );
}

function CorpusHeader({
  latestScanId,
  loadCorpus,
  corpusState,
  corpusFilters,
  updateCorpusFilter,
  compact,
}) {
  return (
    <>
      <div className="section-heading compact">
        <div>
          <span className="eyebrow">{compact ? 'History' : 'Traffic corpus'}</span>
          <h2>Requests</h2>
        </div>
        <button className="secondary-button" onClick={() => loadCorpus()} disabled={!latestScanId || corpusState === 'loading'}>
          {corpusState === 'loading' ? 'Loading' : 'Load'}
        </button>
      </div>
      <div className="corpus-filters">
        <label>
          <span>Method</span>
          <select value={corpusFilters.method} onChange={(e) => updateCorpusFilter('method', e.target.value)}>
            <option value="">Any</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="PATCH">PATCH</option>
            <option value="DELETE">DELETE</option>
          </select>
        </label>
        <label>
          <span>Source</span>
          <select value={corpusFilters.source} onChange={(e) => updateCorpusFilter('source', e.target.value)}>
            <option value="">Any</option>
            <option value="crawler">crawler</option>
            <option value="import">import</option>
            <option value="manual">manual</option>
            <option value="replay">replay</option>
            <option value="fuzzer">fuzzer</option>
            <option value="proof">proof</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <input value={corpusFilters.statusCode} onChange={(e) => updateCorpusFilter('statusCode', e.target.value)} />
        </label>
        <label>
          <span>Path</span>
          <input value={corpusFilters.pathContains} onChange={(e) => updateCorpusFilter('pathContains', e.target.value)} />
        </label>
      </div>
    </>
  );
}

function CorpusViewer({ requests, selectedExchange, onSelect }) {
  return (
    <div className="corpus-viewer">
      <RequestHistory requests={requests} selectedExchange={selectedExchange} onSelect={onSelect} />
      <ExchangeDetail exchange={selectedExchange} />
    </div>
  );
}

function RequestHistory({ requests, selectedExchange, onSelect }) {
  return (
    <div className="request-table" role="table" aria-label="Corpus requests">
      {requests.length === 0 ? (
        <p className="empty-state">No requests loaded.</p>
      ) : requests.map((item) => (
        <button
          className={`request-row ${selectedExchange?.request?.request_id === item.request_id ? 'selected' : ''}`}
          key={item.request_id}
          onClick={() => onSelect(item.request_id)}
        >
          <span className={`method method-${(item.method || 'GET').toLowerCase()}`}>{item.method}</span>
          <span className="request-url">{item.url}</span>
          <span>{item.source}</span>
          <span>{item.auth_role || 'anonymous'}</span>
        </button>
      ))}
    </div>
  );
}

function ExchangeDetail({ exchange }) {
  if (!exchange?.request) {
    return (
      <div className="exchange-detail">
        <p className="empty-state">Select a request.</p>
      </div>
    );
  }
  const request = exchange.request;
  const response = exchange.response || {};
  return (
    <div className="exchange-detail">
      <div className="detail-header">
        <strong>{request.method} {request.normalized_endpoint || request.url}</strong>
        <span>{response.status_code || 'no response'}</span>
      </div>
      <DetailBlock title="Request Headers" value={request.headers} />
      <DetailBlock title="Request Body" value={request.body} />
      <DetailBlock title="Response Headers" value={response.headers} />
      <DetailBlock title="Response Body" value={response.body_excerpt} />
    </div>
  );
}

function TerminalPanel({ terminalRef }) {
  return (
    <section id="terminal" className="terminal-panel">
      <div className="section-heading compact">
        <div>
          <span className="eyebrow">Command view</span>
          <h2>Terminal</h2>
        </div>
      </div>
      <div ref={terminalRef} className="terminal-container" />
    </section>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  );
}

function KpiTile({ label, value, tone }) {
  return (
    <div className={`kpi-tile kpi-${tone}`}>
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  );
}

function SeverityDonut({ counts }) {
  const total = Math.max(1, Object.values(counts).reduce((sum, value) => sum + value, 0));
  const critical = Math.round((counts.critical / total) * 100);
  const high = Math.round((counts.high / total) * 100);
  const medium = Math.round((counts.medium / total) * 100);
  return (
    <div className="donut-wrap">
      <div
        className="severity-donut"
        style={{
          background: `conic-gradient(#e25555 0 ${critical}%, #f28b50 ${critical}% ${critical + high}%, #f5c84b ${critical + high}% ${critical + high + medium}%, #6bb6ff ${critical + high + medium}% 100%)`,
        }}
      >
        <span>{total === 1 && Object.values(counts).every((value) => value === 0) ? 0 : total}</span>
      </div>
      <div className="legend-grid">
        {Object.entries(counts).map(([label, value]) => (
          <span key={label}><i className={`legend-${label}`} />{label}: {value}</span>
        ))}
      </div>
    </div>
  );
}

function SeverityMatrix({ counts }) {
  const columns = ['critical', 'high', 'medium', 'low', 'info'];
  const rows = ['new', 'open', 'proof', 'closed'];
  return (
    <div className="severity-matrix">
      {rows.map((row, rowIndex) => columns.map((column, columnIndex) => {
        const base = counts[column] || 0;
        const value = row === 'new' ? base : Math.max(0, Math.round(base / (rowIndex + columnIndex + 2)));
        return <span className={`matrix-cell cell-${column}`} key={`${row}-${column}`}>{value}</span>;
      }))}
    </div>
  );
}

function CategoryBars({ rows }) {
  if (!rows.length) return <p className="empty-state">No categories yet.</p>;
  const max = Math.max(...rows.map((row) => row.count), 1);
  return (
    <div className="category-bars">
      {rows.slice(0, 6).map((row) => (
        <div className="category-row" key={row.label}>
          <span>{row.label}</span>
          <i><b style={{ width: `${Math.max(8, (row.count / max) * 100)}%` }} /></i>
          <strong>{row.count}</strong>
        </div>
      ))}
    </div>
  );
}

function Timeline({ points }) {
  const safePoints = points.length ? points : [0, 0, 0, 0, 0];
  const max = Math.max(...safePoints, 1);
  const coords = safePoints.map((point, index) => {
    const x = (index / Math.max(1, safePoints.length - 1)) * 100;
    const y = 92 - (point / max) * 74;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg className="timeline-chart" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={`0,94 ${coords} 100,94`} className="timeline-fill" />
      <polyline points={coords} className="timeline-line" />
      {safePoints.map((point, index) => {
        const x = (index / Math.max(1, safePoints.length - 1)) * 100;
        const y = 92 - (point / max) * 74;
        return <circle key={`${point}-${index}`} cx={x} cy={y} r="1.7" className="timeline-dot" />;
      })}
    </svg>
  );
}

function DetailBlock({ title, value }) {
  return (
    <div className="detail-block">
      <span>{title}</span>
      <pre>{formatDetail(value)}</pre>
    </div>
  );
}

function formatDetail(value) {
  if (value === undefined || value === null || value === '') return 'none';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (error) {
    return String(value);
  }
}

function scanPayloadTitle(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname || 'Wraith scan';
  } catch (error) {
    return url || 'Wraith scan';
  }
}

function buildDashboard(status, requests, events, scanPayload) {
  const findings = status?.canonical_findings || status?.findings || [];
  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const categories = {};
  findings.forEach((finding) => {
    const severity = String(finding.severity || 'info').toLowerCase();
    if (severityCounts[severity] !== undefined) severityCounts[severity] += 1;
    else severityCounts.info += 1;
    const type = finding.vuln_type || finding.type || 'unknown';
    categories[type] = (categories[type] || 0) + 1;
  });
  const totalFindings = status?.total_vulnerabilities ?? findings.length;
  const confirmedFindings = findings.filter((finding) => (
    ['succeeded', 'partial'].includes(String(finding.proof_status || '').toLowerCase())
    || Number(finding.confidence || 0) >= 85
  )).length;
  return {
    totalFindings,
    confirmedFindings,
    requestCount: requests.length,
    importCount: countImports(status?.api_imports || scanPayload.imports),
    severityCounts,
    categoryRows: Object.entries(categories)
      .map(([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count),
    timeline: buildTimeline(events, totalFindings),
  };
}

function buildTimeline(events, totalFindings) {
  if (!events.length) return [0, 0, 0, 0, totalFindings || 0];
  const points = [];
  let current = 0;
  events.slice().reverse().forEach((event) => {
    if (['success', 'warning', 'phase'].includes(event.type)) current += 1;
    points.push(current);
  });
  if (totalFindings && points.length) points[points.length - 1] = totalFindings;
  return points.slice(-8);
}

function buildScanPayload(form) {
  const payload = {
    url: form.targetUrl.trim(),
  };
  const depth = parseInt(form.depth, 10);
  const timeout = parseInt(form.timeout, 10);
  if (Number.isFinite(depth)) payload.depth = depth;
  if (Number.isFinite(timeout)) payload.timeout = timeout;

  const auth = {
    type: form.authType,
    role: form.authRole || (form.authType === 'anonymous' ? 'anonymous' : 'authenticated'),
    safety_mode: form.safetyMode,
  };
  const headers = parseKeyValueLines(form.headers);
  const cookies = parseKeyValueLines(form.cookies);
  if (Object.keys(headers).length) auth.headers = headers;
  if (Object.keys(cookies).length) auth.cookies = cookies;
  if (form.bearerToken.trim()) {
    auth.token = form.bearerToken.trim();
    auth.bearer_token = form.bearerToken.trim();
  }
  if (form.storageStatePath.trim()) auth.storage_state_path = form.storageStatePath.trim();
  if (form.healthUrl.trim() || form.healthText.trim()) {
    auth.session_health_check = {
      health_check_url: form.healthUrl.trim(),
      expected_text: form.healthText.trim(),
    };
  }
  payload.auth = auth;

  const graphqlPaths = parseList(form.graphqlImports);
  payload.imports = {
    openapi: parseList(form.openapiImports),
    postman: parseList(form.postmanImports),
    har: parseList(form.harImports),
    graphql: form.graphqlEndpoint.trim()
      ? graphqlPaths.map((path) => ({ path, endpoint_url: form.graphqlEndpoint.trim() }))
      : graphqlPaths,
  };

  payload.sequence_workflows = parseList(form.sequenceWorkflows);
  return payload;
}

function parseList(value) {
  return String(value || '')
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseKeyValueLines(value) {
  return parseList(value).reduce((out, line) => {
    const index = line.includes('=') ? line.indexOf('=') : line.indexOf(':');
    if (index <= 0) return out;
    const key = line.slice(0, index).trim();
    const val = line.slice(index + 1).trim();
    if (key) out[key] = val;
    return out;
  }, {});
}

function countImports(imports) {
  if (!imports) return 0;
  if (typeof imports === 'number') return imports;
  return Object.values(imports).reduce((total, value) => {
    if (Array.isArray(value)) return total + value.length;
    if (typeof value === 'number') return total + value;
    return total + (value ? 1 : 0);
  }, 0);
}

function printBanner(term) {
  term.writeln('');
  term.writeln(c('38;5;117', ' Wraith v4 Workbench'));
  term.writeln(c('38;5;245', ' DAST + SAST + API imports + sequence workflows'));
  term.writeln(c('38;5;245', ' Use the website controls or type help.'));
  term.writeln('');
}

function ensureTerminalApi(term) {
  const noop = () => {};
  if (typeof term.loadAddon !== 'function') term.loadAddon = noop;
  if (typeof term.open !== 'function') term.open = noop;
  if (typeof term.writeln !== 'function') term.writeln = noop;
  if (typeof term.write !== 'function') term.write = noop;
  if (typeof term.clear !== 'function') term.clear = noop;
  if (typeof term.dispose !== 'function') term.dispose = noop;
  if (typeof term.onData !== 'function') term.onData = () => ({ dispose: noop });
}

function printPrompt(term) {
  term.write(c('38;5;117', 'wraith') + c('38;5;245', ' > '));
}

function formatProgressLine(message, type) {
  const text = message || '';
  switch (type) {
    case 'phase':
      return c('38;5;117', `[phase] ${text}`);
    case 'success':
      return c('38;5;108', `[ok] ${text}`);
    case 'error':
      return c('38;5;203', `[err] ${text}`);
    case 'warning':
      return c('38;5;179', `[warn] ${text}`);
    case 'info':
    default:
      return c('38;5;245', `[info] ${text}`);
  }
}

async function executeCommand(command, term, callbacks) {
  const parts = command.trim().split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1);

  try {
    switch (cmd) {
      case 'scan': {
        if (!args[0]) {
          term.writeln(c('38;5;203', '[err] URL required. Usage: scan <url>'));
          return;
        }
        const url = args[0];
        const depthIdx = args.indexOf('--depth');
        const timeoutIdx = args.indexOf('--timeout');
        const depth = depthIdx >= 0 ? parseInt(args[depthIdx + 1], 10) : undefined;
        const timeout = timeoutIdx >= 0 ? parseInt(args[timeoutIdx + 1], 10) : undefined;
        const payload = { url };
        if (Number.isFinite(depth)) payload.depth = depth;
        if (Number.isFinite(timeout)) payload.timeout = timeout;
        const response = await axios.post(`${API_URL}/api/scan`, payload);
        const scanId = response.data.scan_id;
        callbacks.setLatestScanId(scanId);
        term.writeln(c('38;5;108', `[ok] Scan started: ${scanId}`));
        break;
      }
      case 'scanrepo': {
        if (!args[0]) {
          term.writeln(c('38;5;203', '[err] Repo URL required. Usage: scanrepo <github-url>'));
          return;
        }
        const tokenIdx = args.indexOf('--token');
        const branchIdx = args.indexOf('--branch');
        const payload = { url: args[0] };
        if (tokenIdx >= 0) payload.token = args[tokenIdx + 1];
        if (branchIdx >= 0) payload.branch = args[branchIdx + 1];
        const response = await axios.post(`${API_URL}/api/scan/repo`, payload);
        const scanId = response.data.scan_id;
        callbacks.setLatestScanId(scanId);
        term.writeln(c('38;5;108', `[ok] SAST scan started: ${scanId}`));
        break;
      }
      case 'status': {
        if (!args[0]) {
          term.writeln(c('38;5;203', '[err] Scan ID required. Usage: status <id>'));
          return;
        }
        const response = await axios.get(`${API_URL}/api/scan/${args[0]}`);
        callbacks.setScanStatus(response.data);
        term.writeln('');
        term.writeln(c('38;5;117', `Scan ${response.data.scan_id}`));
        term.writeln(`  target: ${response.data.target || ''}`);
        term.writeln(`  status: ${response.data.status || ''}`);
        term.writeln(`  findings: ${response.data.total_vulnerabilities || 0}`);
        term.writeln('');
        break;
      }
      case 'download': {
        if (!args[0]) {
          term.writeln(c('38;5;203', '[err] Scan ID required. Usage: download <id>'));
          return;
        }
        window.open(`${API_URL}/api/download/${args[0]}`, '_blank');
        term.writeln(c('38;5;108', `[ok] PDF download opened for ${args[0]}`));
        break;
      }
      case 'help': {
        term.writeln('');
        term.writeln(c('38;5;117', 'Commands'));
        term.writeln('  scan <url> [--depth 3] [--timeout 20]');
        term.writeln('  scanrepo <github-url> [--token ghp_xxx] [--branch main]');
        term.writeln('  status <id>');
        term.writeln('  download <id>');
        term.writeln('  clear');
        term.writeln('');
        break;
      }
      case 'clear':
      case 'cls':
        term.clear();
        printBanner(term);
        break;
      default:
        term.writeln(c('38;5;203', `[err] Unknown command: ${cmd}`));
    }
  } catch (error) {
    if (error?.code === 'ERR_NETWORK') {
      term.writeln(c('38;5;203', `[err] API server not reachable at ${API_URL}`));
      term.writeln(c('38;5;245', 'Start backend with: python api_server.py'));
      return;
    }
    term.writeln(c('38;5;203', `[err] ${error.message}`));
    if (error.response?.data?.error) {
      term.writeln(c('38;5;245', error.response.data.error));
    }
  }
}

export default App;
