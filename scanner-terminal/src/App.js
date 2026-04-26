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

function App() {
  const terminalRef = useRef(null);
  const fitAddonRef = useRef(null);
  const termRef = useRef(null);
  const [terminal, setTerminal] = useState(null);
  const [socketState, setSocketState] = useState('connecting');
  const [form, setForm] = useState(initialForm);
  const [launchState, setLaunchState] = useState('idle');
  const [latestScanId, setLatestScanId] = useState('');
  const [scanStatus, setScanStatus] = useState(null);
  const [progressEvents, setProgressEvents] = useState([]);

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

  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: '"Fira Code", "Cascadia Code", "JetBrains Mono", Consolas, monospace',
      theme: {
        background: '#101113',
        foreground: '#d7d2c6',
        cursor: '#e7b75f',
        cursorAccent: '#101113',
        black: '#101113',
        red: '#ef5f57',
        green: '#8fbf71',
        yellow: '#e7b75f',
        blue: '#6aa4d9',
        magenta: '#c69ad9',
        cyan: '#65c3ad',
        white: '#d7d2c6',
        brightBlack: '#5d6268',
        brightRed: '#ff7b72',
        brightGreen: '#a6d189',
        brightYellow: '#f4bf75',
        brightBlue: '#8ab4f8',
        brightMagenta: '#d2a6ff',
        brightCyan: '#8bd5ca',
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
    };
  }, [addProgress]);

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

  const submitScan = async (event) => {
    event.preventDefault();
    if (!scanPayload.url) return;
    setLaunchState('running');
    setScanStatus(null);
    try {
      const response = await axios.post(`${API_URL}/api/scan`, scanPayload);
      const scanId = response.data.scan_id;
      setLatestScanId(scanId);
      addProgress({
        scan_id: scanId,
        type: 'success',
        message: `Scan started from setup panel: ${scanId}`,
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

  const refreshStatus = async () => {
    if (!latestScanId) return;
    try {
      const response = await axios.get(`${API_URL}/api/scan/${latestScanId}`);
      setScanStatus(response.data);
    } catch (error) {
      addProgress({
        scan_id: latestScanId,
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const importCount = countImports(scanPayload.imports);
  const workflowCount = (scanPayload.sequence_workflows || []).length;

  return (
    <div className="App">
      <header className="titlebar">
        <div className="titlebar-dots" aria-hidden="true">
          <span className="dot dot-red" />
          <span className="dot dot-yellow" />
          <span className="dot dot-green" />
        </div>
        <span className="titlebar-title">Wraith Workbench</span>
        <span className={`socket-pill socket-${socketState}`}>{socketState}</span>
      </header>

      <div className="workbench">
        <aside className="sidebar">
          <div className="brand-block">
            <span className="brand-mark">W</span>
            <div>
              <strong>Wraith v4</strong>
              <span>VA setup</span>
            </div>
          </div>
          <nav className="nav-stack" aria-label="Workbench sections">
            <a href="#scan-setup">Setup</a>
            <a href="#scan-progress">Progress</a>
            <a href="#terminal">Terminal</a>
          </nav>
          <div className="sidebar-metrics">
            <Metric label="Imports" value={importCount} />
            <Metric label="Workflows" value={workflowCount} />
            <Metric label="Mode" value={form.safetyMode} />
          </div>
        </aside>

        <main className="main-grid">
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
          </section>

          <section id="scan-progress" className="progress-panel">
            <div className="section-heading compact">
              <div>
                <span className="eyebrow">Run state</span>
                <h2>Progress</h2>
              </div>
              <button className="secondary-button" onClick={refreshStatus} disabled={!latestScanId}>Refresh</button>
            </div>
            <StatusSummary scanId={latestScanId} status={scanStatus} launchState={launchState} />
            <div className="event-list" aria-live="polite">
              {progressEvents.length === 0 ? (
                <p className="empty-state">No scan events yet.</p>
              ) : progressEvents.map((event, index) => (
                <div className={`event-row event-${event.type}`} key={`${event.timestamp}-${index}`}>
                  <span>{event.type}</span>
                  <p>{event.message}</p>
                </div>
              ))}
            </div>
          </section>

          <section id="terminal" className="terminal-panel">
            <div className="section-heading compact">
              <div>
                <span className="eyebrow">Command view</span>
                <h2>Terminal</h2>
              </div>
            </div>
            <div ref={terminalRef} className="terminal-container" />
          </section>
        </main>
      </div>
    </div>
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
  term.writeln(c('38;5;214', ' Wraith v4 Workbench'));
  term.writeln(c('38;5;245', ' DAST + SAST + API imports + sequence workflows'));
  term.writeln(c('38;5;245', ' Use the setup panel or type help.'));
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
  term.write(c('38;5;214', 'wraith') + c('38;5;245', ' > ') );
}

function formatProgressLine(message, type) {
  const text = message || '';
  switch (type) {
    case 'phase':
      return c('38;5;214', `[phase] ${text}`);
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
        term.writeln(c('38;5;214', `Scan ${response.data.scan_id}`));
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
        term.writeln(c('38;5;214', 'Commands'));
        term.writeln('  scan <url> [--depth 3] [--timeout 20]');
        term.writeln('  scanrepo <github-url> [--token ghp_xxx] [--branch main]');
        term.writeln('  status <id>');
        term.writeln('  download <id>');
        term.writeln('  clear');
        term.writeln(c('38;5;245', 'Use the setup panel for auth profiles, imports, and sequence workflows.'));
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
