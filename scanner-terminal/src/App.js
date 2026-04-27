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

const initialIntruderConfig = {
  marker: '{{payload}}',
  payloads: 'wraith-test\nwraith_probe\n%27',
  delayMs: '150',
  maxRequests: '25',
};

const DEFAULT_REPEATER_TAB_ID = 'repeater_default';

function initialViewFromLocation() {
  const hash = String(window.location.hash || '').toLowerCase();
  if (['#scan-setup', '#result-dashboard', '#traffic-corpus', '#terminal', '#automated', '#issues', '#scan-details', '#reporting'].includes(hash)) {
    return 'automated';
  }
  if (['#proxy-history', '#replay', '#response', '#manual', '#intruder', '#decoder', '#manual-reporting'].includes(hash)) {
    return 'manual';
  }
  if (hash === '#start' || hash === '#mode') return 'mode';
  return 'home';
}

function initialAutomatedTabFromLocation() {
  const hash = String(window.location.hash || '').toLowerCase();
  if (hash === '#issues') return 'issues';
  if (hash === '#traffic-corpus') return 'urls';
  if (hash === '#scan-setup' || hash === '#scan-details') return 'details';
  if (hash === '#terminal' || hash === '#reporting') return 'reporting';
  return 'overview';
}

function initialManualTabFromLocation() {
  const hash = String(window.location.hash || '').toLowerCase();
  if (hash === '#replay' || hash === '#response') return 'repeater';
  if (hash === '#intruder') return 'intruder';
  if (hash === '#decoder') return 'decoder';
  if (hash === '#manual-reporting' || hash === '#terminal') return 'reporting';
  return 'proxy';
}

function App() {
  const terminalRef = useRef(null);
  const fitAddonRef = useRef(null);
  const termRef = useRef(null);
  const intruderAbortRef = useRef(false);
  const [terminal, setTerminal] = useState(null);
  const [view, setViewState] = useState(initialViewFromLocation);
  const [automatedTab, setAutomatedTab] = useState(initialAutomatedTabFromLocation);
  const [manualTab, setManualTab] = useState(initialManualTabFromLocation);
  const [socketState, setSocketState] = useState('idle');
  const [form, setForm] = useState(initialForm);
  const [manualRequest, setManualRequest] = useState(initialManualRequest);
  const [repeaterTabs, setRepeaterTabs] = useState([{
    tabId: DEFAULT_REPEATER_TAB_ID,
    title: 'Manual request',
    request: initialManualRequest,
    sourceRequestId: '',
    attempts: [],
    activeAttemptId: '',
  }]);
  const [activeRepeaterTabId, setActiveRepeaterTabId] = useState(DEFAULT_REPEATER_TAB_ID);
  const [manualState, setManualState] = useState('idle');
  const [intruderConfig, setIntruderConfig] = useState(initialIntruderConfig);
  const [intruderState, setIntruderState] = useState('idle');
  const [intruderResults, setIntruderResults] = useState([]);
  const [selectedIntruderResultId, setSelectedIntruderResultId] = useState('');
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
  const [proxyStatus, setProxyStatus] = useState({ running: false });
  const [proxyState, setProxyState] = useState('idle');
  const [pendingProxyRequests, setPendingProxyRequests] = useState([]);

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
  const activeRepeaterTab = useMemo(
    () => repeaterTabs.find((tab) => tab.tabId === activeRepeaterTabId) || repeaterTabs[0],
    [activeRepeaterTabId, repeaterTabs],
  );
  const selectedIntruderResult = useMemo(
    () => intruderResults.find((result) => result.resultId === selectedIntruderResultId) || intruderResults[intruderResults.length - 1] || null,
    [intruderResults, selectedIntruderResultId],
  );

  const setView = useCallback((nextView) => {
    setViewState(nextView);
    if (nextView === 'automated') setAutomatedTab('overview');
    if (nextView === 'manual') setManualTab('proxy');
    const hashByView = {
      home: '',
      mode: '#start',
      automated: '#result-dashboard',
      manual: '#proxy-history',
    };
    const nextHash = hashByView[nextView] || '';
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, '', `${window.location.pathname}${nextHash}`);
    }
  }, []);

  useEffect(() => {
    const syncHash = () => {
      setViewState(initialViewFromLocation());
      setAutomatedTab(initialAutomatedTabFromLocation());
      setManualTab(initialManualTabFromLocation());
    };
    window.addEventListener('hashchange', syncHash);
    return () => window.removeEventListener('hashchange', syncHash);
  }, []);

  useEffect(() => {
    setSocketState('connecting');
    const ws = io(API_URL) || { on: () => {}, disconnect: () => {} };
    ws.on('connect', () => {
      setSocketState('connected');
      if (termRef.current) termRef.current.writeln(c('38;5;108', '[ws] connected to api server'));
    });
    ws.on('scan_progress', (event) => {
      addProgress(event);
      if (termRef.current) termRef.current.writeln(formatProgressLine(event.message, event.type));
    });
    ws.on('disconnect', () => {
      setSocketState('disconnected');
      if (termRef.current) termRef.current.writeln(c('38;5;203', '[ws] connection lost'));
    });
    ws.on('connect_error', () => {
      setSocketState('error');
      if (termRef.current) termRef.current.writeln(c('38;5;203', `[ws] unable to reach api server at ${API_URL}`));
    });
    return () => {
      ws.disconnect();
      setSocketState('idle');
    };
  }, [addProgress]);

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

    const handleResize = () => {
      if (typeof fitAddon.fit === 'function') fitAddon.fit();
    };
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      term.dispose();
      termRef.current = null;
      setTerminal(null);
    };
  }, [view, automatedTab, manualTab]);

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

  const applyManualRequestUpdate = (updater) => {
    setManualRequest((current) => {
      const next = typeof updater === 'function' ? updater(current) : updater;
      const normalized = { ...current, ...next };
      setRepeaterTabs((tabs) => tabs.map((tab) => (
        tab.tabId === activeRepeaterTabId
          ? { ...tab, title: repeaterTitle(normalized), request: normalized }
          : tab
      )));
      return normalized;
    });
  };

  const updateManualRequest = (name, value) => {
    applyManualRequestUpdate((current) => ({ ...current, [name]: value }));
  };

  const updateIntruderConfig = (name, value) => {
    setIntruderConfig((current) => ({ ...current, [name]: value }));
  };

  const selectRepeaterTab = (tabId) => {
    const tab = repeaterTabs.find((item) => item.tabId === tabId);
    if (!tab) return;
    setActiveRepeaterTabId(tabId);
    setManualRequest(tab.request);
    const activeAttempt = selectedRepeaterAttempt(tab);
    setSelectedExchange(activeAttempt?.exchange || null);
    setManualTab('repeater');
  };

  const createRepeaterTab = () => {
    const request = {
      ...initialManualRequest,
      scanId: manualRequest.scanId || latestScanId,
    };
    const tab = {
      tabId: `rep_${Date.now().toString(36)}`,
      title: 'New request',
      request,
      sourceRequestId: '',
      attempts: [],
      activeAttemptId: '',
    };
    setRepeaterTabs((current) => [...current, tab]);
    setActiveRepeaterTabId(tab.tabId);
    setManualRequest(request);
    setManualTab('repeater');
    window.history.replaceState(null, '', `${window.location.pathname}#replay`);
  };

  const closeRepeaterTab = (tabId) => {
    setRepeaterTabs((current) => {
      if (current.length <= 1) return current;
      const index = current.findIndex((tab) => tab.tabId === tabId);
      const next = current.filter((tab) => tab.tabId !== tabId);
      if (tabId === activeRepeaterTabId) {
        const replacement = next[Math.max(0, index - 1)] || next[0];
        setActiveRepeaterTabId(replacement.tabId);
        setManualRequest(replacement.request);
        const activeAttempt = selectedRepeaterAttempt(replacement);
        setSelectedExchange(activeAttempt?.exchange || null);
      }
      return next;
    });
  };

  const selectRepeaterAttempt = (attemptId) => {
    setRepeaterTabs((current) => current.map((tab) => {
      if (tab.tabId !== activeRepeaterTabId) return tab;
      const attempt = (tab.attempts || []).find((item) => item.attemptId === attemptId);
      if (attempt) setSelectedExchange(attempt.exchange || null);
      return { ...tab, activeAttemptId: attemptId };
    }));
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
      applyManualRequestUpdate((current) => ({ ...current, scanId }));
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
      applyManualRequestUpdate((current) => ({ ...current, scanId }));
      const exchange = {
        request: response.data.request,
        response: response.data.response,
      };
      setSelectedExchange(exchange);
      const attempt = buildRepeaterAttempt(response.data.request, response.data.response);
      setRepeaterTabs((tabs) => tabs.map((tab) => (
        tab.tabId === activeRepeaterTabId
          ? {
              ...tab,
              attempts: [attempt, ...(tab.attempts || [])].slice(0, 50),
              activeAttemptId: attempt.attemptId,
              request: { ...tab.request, scanId },
            }
          : tab
      )));
      await loadCorpus(scanId);
      setSelectedExchange(exchange);
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

  const refreshProxyStatus = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/manual/proxy/status`);
      setProxyStatus(response.data || { running: false });
    } catch (error) {
      addProgress({
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const startManualProxy = async () => {
    setProxyState('starting');
    try {
      const origin = safeOrigin(manualRequest.url) || safeOrigin(form.targetUrl) || 'http://127.0.0.1:5000';
      const response = await axios.post(`${API_URL}/api/manual/proxy/start`, {
        scan_id: manualRequest.scanId || latestScanId,
        target_base_url: origin,
        scope: [origin],
        auth_role: 'manual',
        intercept_enabled: false,
      });
      const status = response.data || {};
      setProxyStatus(status);
      setProxyState('running');
      if (status.scan_id) {
        setLatestScanId(status.scan_id);
        applyManualRequestUpdate((current) => ({ ...current, scanId: status.scan_id }));
      }
      addProgress({
        scan_id: status.scan_id,
        type: 'success',
        message: `Manual proxy listening on ${status.host}:${status.port}`,
      });
    } catch (error) {
      setProxyState('error');
      addProgress({
        scan_id: manualRequest.scanId || latestScanId,
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const stopManualProxy = async () => {
    setProxyState('stopping');
    try {
      const response = await axios.post(`${API_URL}/api/manual/proxy/stop`);
      setProxyStatus(response.data || { running: false });
      setPendingProxyRequests([]);
      setProxyState('stopped');
    } catch (error) {
      setProxyState('error');
      addProgress({
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const toggleManualProxyIntercept = async (enabled) => {
    try {
      const response = await axios.post(`${API_URL}/api/manual/proxy/intercept`, { enabled });
      setProxyStatus(response.data || { running: false });
    } catch (error) {
      addProgress({
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const loadProxyPending = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/manual/proxy/pending`);
      setPendingProxyRequests(response.data.requests || []);
    } catch (error) {
      addProgress({
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const decideProxyRequest = async (requestId, action, requestUpdate) => {
    try {
      const payload = { action };
      if (requestUpdate) payload.request = requestUpdate;
      await axios.post(`${API_URL}/api/manual/proxy/pending/${requestId}`, payload);
      await loadProxyPending();
      if (action === 'forward') {
        setTimeout(() => loadCorpus(manualRequest.scanId || latestScanId), 300);
      }
    } catch (error) {
      addProgress({
        type: 'error',
        message: error?.response?.data?.error || error.message,
      });
    }
  };

  const sendRequestToRepeater = (requestRecord) => {
    if (!requestRecord) return;
    const nextRequest = manualRequestFromRecord(requestRecord, manualRequest, latestScanId);
    const sourceRequestId = requestRecord.request_id || '';
    const existingTab = repeaterTabs.find((tab) => tab.sourceRequestId && tab.sourceRequestId === sourceRequestId);
    if (existingTab) {
      setRepeaterTabs((current) => current.map((tab) => (
        tab.tabId === existingTab.tabId
          ? { ...tab, title: repeaterTitle(nextRequest), request: nextRequest }
          : tab
      )));
      setActiveRepeaterTabId(existingTab.tabId);
    } else {
      const tab = {
        tabId: `rep_${sourceRequestId || Date.now().toString(36)}`,
        title: repeaterTitle(nextRequest),
        request: nextRequest,
        sourceRequestId,
        attempts: [],
        activeAttemptId: '',
      };
      setRepeaterTabs((current) => [...current, tab]);
      setActiveRepeaterTabId(tab.tabId);
    }
    setManualRequest(nextRequest);
    setManualTab('repeater');
    setViewState('manual');
    window.history.replaceState(null, '', `${window.location.pathname}#replay`);
  };

  const sendRequestToIntruder = (requestRecord) => {
    if (!requestRecord) return;
    const nextRequest = manualRequestFromRecord(requestRecord, manualRequest, latestScanId);
    setManualRequest(nextRequest);
    setManualTab('intruder');
    setViewState('manual');
    window.history.replaceState(null, '', `${window.location.pathname}#intruder`);
  };

  const sendIntruderResultToRepeater = (result) => {
    const requestRecord = result?.exchange?.request;
    if (requestRecord) sendRequestToRepeater(requestRecord);
  };

  const selectIntruderResult = (resultId) => {
    const result = intruderResults.find((item) => item.resultId === resultId);
    setSelectedIntruderResultId(resultId);
    if (result?.exchange) setSelectedExchange(result.exchange);
  };

  const runIntruder = async () => {
    const payloads = parseList(intruderConfig.payloads);
    const maxRequests = Math.max(1, Math.min(parseInt(intruderConfig.maxRequests, 10) || 25, 100));
    const delayMs = Math.max(0, Math.min(parseInt(intruderConfig.delayMs, 10) || 0, 5000));
    const marker = intruderConfig.marker || '{{payload}}';
    const selectedPayloads = payloads.slice(0, maxRequests);
    if (!manualRequest.url.trim() || selectedPayloads.length === 0) return;

    intruderAbortRef.current = false;
    setIntruderState('running');
    setIntruderResults([]);
    setSelectedIntruderResultId('');

    let scanId = manualRequest.scanId || latestScanId;
    let lastExchange = null;
    for (const payload of selectedPayloads) {
      if (intruderAbortRef.current) break;
      const requestForPayload = buildIntruderRequest(manualRequest, marker, payload);
      try {
        const response = await axios.post(`${API_URL}/api/manual/replay`, {
          scan_id: scanId,
          method: requestForPayload.method,
          url: requestForPayload.url.trim(),
          headers: parseKeyValueLines(requestForPayload.headers),
          body: requestForPayload.body,
          timeout: parseInt(requestForPayload.timeout, 10) || 10,
          safety_mode: requestForPayload.safetyMode || 'safe',
          allow_state_change: Boolean(requestForPayload.allowStateChange),
          auth_role: 'manual',
          source: 'fuzzer',
        });
        scanId = response.data.scan_id || scanId;
        const result = buildIntruderResult(payload, response.data.request, response.data.response);
        setLatestScanId(scanId);
        lastExchange = result.exchange;
        setSelectedIntruderResultId(result.resultId);
        setSelectedExchange(result.exchange);
        setIntruderResults((current) => [...current, result]);
      } catch (error) {
        const result = buildIntruderError(payload, error);
        setSelectedIntruderResultId(result.resultId);
        setIntruderResults((current) => [...current, result]);
      }
      if (delayMs) await wait(delayMs);
    }

    setIntruderState(intruderAbortRef.current ? 'stopped' : 'complete');
    if (scanId) applyManualRequestUpdate((current) => ({ ...current, scanId }));
    if (scanId) await loadCorpus(scanId);
    if (lastExchange) setSelectedExchange(lastExchange);
  };

  const stopIntruder = () => {
    intruderAbortRef.current = true;
    setIntruderState('stopping');
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
          activeTab={automatedTab}
          setActiveTab={setAutomatedTab}
        />
      )}
      {view === 'manual' && (
        <ManualPage
          manualRequest={manualRequest}
          updateManualRequest={updateManualRequest}
          sendManualReplay={sendManualReplay}
          intruderConfig={intruderConfig}
          updateIntruderConfig={updateIntruderConfig}
          runIntruder={runIntruder}
          stopIntruder={stopIntruder}
          intruderState={intruderState}
          intruderResults={intruderResults}
          selectedIntruderResult={selectedIntruderResult}
          selectedIntruderResultId={selectedIntruderResultId}
          selectIntruderResult={selectIntruderResult}
          sendIntruderResultToRepeater={sendIntruderResultToRepeater}
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
          activeTab={manualTab}
          setActiveTab={setManualTab}
          repeaterTabs={repeaterTabs}
          activeRepeaterTabId={activeRepeaterTabId}
          activeRepeaterTab={activeRepeaterTab}
          selectRepeaterTab={selectRepeaterTab}
          selectRepeaterAttempt={selectRepeaterAttempt}
          createRepeaterTab={createRepeaterTab}
          closeRepeaterTab={closeRepeaterTab}
          proxyStatus={proxyStatus}
          proxyState={proxyState}
          pendingProxyRequests={pendingProxyRequests}
          refreshProxyStatus={refreshProxyStatus}
          startManualProxy={startManualProxy}
          stopManualProxy={stopManualProxy}
          toggleManualProxyIntercept={toggleManualProxyIntercept}
          loadProxyPending={loadProxyPending}
          decideProxyRequest={decideProxyRequest}
          sendRequestToRepeater={sendRequestToRepeater}
          sendRequestToIntruder={sendRequestToIntruder}
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
  activeTab,
  setActiveTab,
}) {
  const findings = scanStatus?.canonical_findings || scanStatus?.findings || [];
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
          activeTab={activeTab}
          onChange={setActiveTab}
          tabs={[
            ['overview', 'Overview'],
            ['issues', 'Issues'],
            ['urls', 'Scanned URLs'],
            ['details', 'Scan details'],
            ['reporting', 'Reporting & logs'],
          ]}
        />

        <div className={`workspace-tab-panel automated-tab automated-tab-${activeTab}`}>
          {activeTab === 'overview' && (
            <>
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
              <section className="progress-panel overview-progress">
                <div className="section-heading compact">
                  <div>
                    <span className="eyebrow">Run state</span>
                    <h2>Progress</h2>
                  </div>
                </div>
                <StatusSummary scanId={latestScanId} status={scanStatus} launchState={launchState} />
                <ProgressEvents events={progressEvents} />
              </section>
            </>
          )}

          {activeTab === 'issues' && (
            <section id="issues" className="issues-panel">
              <div className="section-heading compact">
                <div>
                  <span className="eyebrow">Findings</span>
                  <h2>Issues</h2>
                </div>
              </div>
              <IssuesTable findings={findings} />
            </section>
          )}

          {activeTab === 'urls' && (
            <section id="traffic-corpus" className="corpus-panel">
              <CorpusHeader
                latestScanId={latestScanId}
                loadCorpus={loadCorpus}
                corpusState={corpusState}
                corpusFilters={corpusFilters}
                updateCorpusFilter={updateCorpusFilter}
              />
              <CorpusViewer
                requests={corpusRequests}
                selectedExchange={selectedExchange}
                onSelect={loadExchange}
              />
            </section>
          )}

          {activeTab === 'details' && (
            <section id="scan-setup" className="setup-panel setup-tab-panel">
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
          )}

          {activeTab === 'reporting' && (
            <section id="reporting" className="reporting-panel">
              <ReportActions scanId={latestScanId} />
              <div className="reporting-grid">
                <section className="progress-panel">
                  <div className="section-heading compact">
                    <div>
                      <span className="eyebrow">Logs</span>
                      <h2>Scan Events</h2>
                    </div>
                  </div>
                  <ProgressEvents events={progressEvents} />
                </section>
                <TerminalPanel terminalRef={terminalRef} />
              </div>
            </section>
          )}
        </div>
      </main>
    </div>
  );
}

function ManualPage({
  manualRequest,
  updateManualRequest,
  sendManualReplay,
  intruderConfig,
  updateIntruderConfig,
  runIntruder,
  stopIntruder,
  intruderState,
  intruderResults,
  selectedIntruderResult,
  selectedIntruderResultId,
  selectIntruderResult,
  sendIntruderResultToRepeater,
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
  activeTab,
  setActiveTab,
  repeaterTabs,
  activeRepeaterTabId,
  activeRepeaterTab,
  selectRepeaterTab,
  selectRepeaterAttempt,
  createRepeaterTab,
  closeRepeaterTab,
  proxyStatus,
  proxyState,
  pendingProxyRequests,
  refreshProxyStatus,
  startManualProxy,
  stopManualProxy,
  toggleManualProxyIntercept,
  loadProxyPending,
  decideProxyRequest,
  sendRequestToRepeater,
  sendRequestToIntruder,
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
          activeTab={activeTab}
          onChange={setActiveTab}
          tabs={[
            ['proxy', 'Proxy history'],
            ['repeater', 'Repeater'],
            ['intruder', 'Intruder'],
            ['decoder', 'Decoder'],
            ['reporting', 'Reporting & logs'],
          ]}
        />

        <div className={`workspace-tab-panel manual-tab manual-tab-${activeTab}`}>
          {activeTab === 'proxy' && (
            <section id="proxy-history" className="history-panel manual-wide-panel">
              <ProxyControlPanel
                proxyStatus={proxyStatus}
                proxyState={proxyState}
                pendingProxyRequests={pendingProxyRequests}
                refreshProxyStatus={refreshProxyStatus}
                startManualProxy={startManualProxy}
                stopManualProxy={stopManualProxy}
                toggleManualProxyIntercept={toggleManualProxyIntercept}
                loadProxyPending={loadProxyPending}
                decideProxyRequest={decideProxyRequest}
              />
              <CorpusHeader
                latestScanId={manualRequest.scanId || latestScanId}
                loadCorpus={loadCorpus}
                corpusState={corpusState}
                corpusFilters={corpusFilters}
                updateCorpusFilter={updateCorpusFilter}
                compact
              />
              <CorpusViewer
                requests={corpusRequests}
                selectedExchange={selectedExchange}
                onSelect={loadExchange}
                onSendToRepeater={sendRequestToRepeater}
                onSendToIntruder={sendRequestToIntruder}
              />
            </section>
          )}

          {activeTab === 'repeater' && (
            <div className="manual-grid repeater-grid">
              <section id="replay" className="replay-panel">
                <RepeaterTabStrip
                  tabs={repeaterTabs}
                  activeTabId={activeRepeaterTabId}
                  onSelect={selectRepeaterTab}
                  onNew={createRepeaterTab}
                  onClose={closeRepeaterTab}
                />
                <div className="section-heading compact">
                  <div>
                    <span className="eyebrow">Repeater</span>
                    <h2>Request</h2>
                  </div>
                  <div className="button-row">
                    <button className="secondary-button" onClick={() => setActiveTab('intruder')}>Intruder</button>
                    <button className="primary-button" onClick={sendManualReplay} disabled={manualState === 'sending'}>
                      {manualState === 'sending' ? 'Sending' : 'Send'}
                    </button>
                  </div>
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
                <RepeaterResponsePanel
                  tab={activeRepeaterTab}
                  selectedExchange={selectedExchange}
                  onSelectAttempt={selectRepeaterAttempt}
                />
              </section>
            </div>
          )}

          {activeTab === 'intruder' && (
            <IntruderPanel
              request={manualRequest}
              updateRequest={updateManualRequest}
              config={intruderConfig}
              updateConfig={updateIntruderConfig}
              onRun={runIntruder}
              onStop={stopIntruder}
              state={intruderState}
              results={intruderResults}
              selectedResult={selectedIntruderResult}
              selectedResultId={selectedIntruderResultId}
              onSelectResult={selectIntruderResult}
              onSendResultToRepeater={sendIntruderResultToRepeater}
            />
          )}
          {activeTab === 'decoder' && <DecoderPanel />}

          {activeTab === 'reporting' && (
            <section id="manual-reporting" className="reporting-panel">
              <ReportActions scanId={manualRequest.scanId || latestScanId} />
              <div className="reporting-grid">
                <TerminalPanel terminalRef={terminalRef} />
              </div>
            </section>
          )}
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

function WorkspaceTabs({ tabs, activeTab, onChange }) {
  return (
    <nav className="workspace-tabs" aria-label="Workspace sections">
      {tabs.map(([key, label]) => (
        <button
          className={key === activeTab ? 'active' : ''}
          key={key}
          onClick={() => {
            onChange(key);
            window.history.replaceState(null, '', `${window.location.pathname}#${tabHash(key)}`);
          }}
        >
          {label}
        </button>
      ))}
    </nav>
  );
}

function tabHash(tab) {
  const mapping = {
    overview: 'result-dashboard',
    issues: 'issues',
    urls: 'traffic-corpus',
    details: 'scan-details',
    reporting: 'reporting',
    proxy: 'proxy-history',
    repeater: 'replay',
    intruder: 'intruder',
    decoder: 'decoder',
  };
  return mapping[tab] || tab;
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

function RepeaterTabStrip({ tabs, activeTabId, onSelect, onNew, onClose }) {
  return (
    <div className="repeater-tab-strip" aria-label="Repeater requests">
      <div className="repeater-tabs">
        {tabs.map((tab) => (
          <div className={tab.tabId === activeTabId ? 'repeater-tab-item active' : 'repeater-tab-item'} key={tab.tabId}>
            <button className="repeater-tab-button" onClick={() => onSelect(tab.tabId)}>
              <span>{tab.title}</span>
            </button>
            {tabs.length > 1 && (
              <button
                className="repeater-tab-close"
                aria-label={`Close ${tab.title}`}
                onClick={(event) => {
                  event.stopPropagation();
                  onClose(tab.tabId);
                }}
              >
                x
              </button>
            )}
          </div>
        ))}
      </div>
      <button className="repeater-new-button" onClick={onNew}>New</button>
    </div>
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

function IntruderPanel({
  request,
  updateRequest,
  config,
  updateConfig,
  onRun,
  onStop,
  state,
  results,
  selectedResult,
  selectedResultId,
  onSelectResult,
  onSendResultToRepeater,
}) {
  const summary = summarizeIntruderResults(results);
  const running = state === 'running' || state === 'stopping';
  const selectedExchange = selectedResult?.exchange || null;
  return (
    <section id="intruder" className="intruder-panel">
      <div className="section-heading compact">
        <div>
          <span className="eyebrow">Intruder</span>
          <h2>Payload Runner</h2>
        </div>
        <div className="button-row">
          <button className="secondary-button" onClick={onStop} disabled={!running}>Stop</button>
          <button className="primary-button" onClick={onRun} disabled={running}>
            {running ? 'Running' : 'Run attack'}
          </button>
        </div>
      </div>
      <div className="intruder-grid">
        <div className="intruder-config">
          <ManualRequestEditor request={request} updateRequest={updateRequest} />
          <div className="intruder-controls">
            <label>
              <span>Payload marker</span>
              <input value={config.marker} onChange={(event) => updateConfig('marker', event.target.value)} />
            </label>
            <label>
              <span>Delay ms</span>
              <input value={config.delayMs} onChange={(event) => updateConfig('delayMs', event.target.value)} />
            </label>
            <label>
              <span>Max requests</span>
              <input value={config.maxRequests} onChange={(event) => updateConfig('maxRequests', event.target.value)} />
            </label>
            <label className="raw-field payload-list">
              <span>Payloads</span>
              <textarea value={config.payloads} onChange={(event) => updateConfig('payloads', event.target.value)} spellCheck="false" />
            </label>
          </div>
        </div>
        <div className="intruder-results">
          <div className="intruder-summary">
            <Metric label="State" value={state} />
            <Metric label="Sent" value={results.length} />
            <Metric label="Clusters" value={summary.clusters} />
            <Metric label="Errors" value={summary.errors} />
          </div>
          <div className="intruder-toolbar">
            <span>{selectedResult ? `Selected: ${selectedResult.payload}` : 'No result selected'}</span>
            <button
              className="secondary-button"
              onClick={() => onSendResultToRepeater(selectedResult)}
              disabled={!selectedExchange}
            >
              Send to Repeater
            </button>
          </div>
          <div className="intruder-table" role="table" aria-label="Intruder results">
            <div className="intruder-row intruder-row-head">
              <span>Payload</span>
              <span>Status</span>
              <span>Length</span>
              <span>Time</span>
              <span>Cluster</span>
            </div>
            {results.length === 0 ? (
              <p className="empty-state">Insert the payload marker into the URL, headers, or body, then run a capped safe-mode attack.</p>
            ) : results.map((result) => (
              <button
                className={result.resultId === selectedResultId ? 'intruder-row active' : 'intruder-row'}
                key={result.resultId}
                onClick={() => onSelectResult(result.resultId)}
              >
                <span title={result.payload}>{result.payload}</span>
                <strong>{result.status}</strong>
                <span>{result.length} B</span>
                <span>{result.timeMs} ms</span>
                <em title={result.error || result.cluster}>{result.error || result.cluster}</em>
              </button>
            ))}
          </div>
          <ExchangeDetail exchange={selectedExchange} />
        </div>
      </div>
    </section>
  );
}

function RepeaterResponsePanel({ tab, selectedExchange, onSelectAttempt }) {
  const attempts = tab?.attempts || [];
  const activeAttempt = selectedRepeaterAttempt(tab);
  const activeExchange = activeAttempt?.exchange || selectedExchange;
  const activeIndex = attempts.findIndex((attempt) => attempt.attemptId === activeAttempt?.attemptId);
  const previousAttempt = activeIndex >= 0 ? attempts[activeIndex + 1] : null;
  return (
    <div className="repeater-response-panel">
      <div className="repeater-attempts">
        {attempts.length === 0 ? (
          <p className="empty-state">No repeater attempts yet.</p>
        ) : attempts.map((attempt, index) => {
          const previous = attempts[index + 1];
          const active = attempt.attemptId === tab.activeAttemptId;
          const response = attempt.exchange?.response || {};
          return (
            <button
              className={active ? 'attempt-row active' : 'attempt-row'}
              key={attempt.attemptId}
              onClick={() => onSelectAttempt(attempt.attemptId)}
            >
              <span>{attempt.label}</span>
              <strong>{response.status_code || 'error'}</strong>
              <span>{response.content_length ?? 0} B</span>
              <span>{response.response_time_ms ?? 0} ms</span>
              <em>{attemptDelta(attempt, previous)}</em>
            </button>
          );
        })}
      </div>
      <ResponseDiffPanel currentAttempt={activeAttempt} previousAttempt={previousAttempt} />
      <ExchangeDetail exchange={activeExchange} />
    </div>
  );
}

function ResponseDiffPanel({ currentAttempt, previousAttempt }) {
  const currentResponse = currentAttempt?.exchange?.response || null;
  const previousResponse = previousAttempt?.exchange?.response || null;
  if (!currentResponse) {
    return null;
  }
  if (!previousResponse) {
    return (
      <div className="response-diff-panel">
        <div className="diff-summary">
          <strong>Diff</strong>
          <span>Run this request again to compare response changes.</span>
        </div>
      </div>
    );
  }
  const lines = buildSimpleDiff(previousResponse.body_excerpt, currentResponse.body_excerpt);
  return (
    <div className="response-diff-panel">
      <div className="diff-summary">
        <strong>Diff vs previous</strong>
        <span>{attemptDelta(currentAttempt, previousAttempt)}</span>
      </div>
      <div className="diff-metrics">
        <Metric label="Status" value={`${previousResponse.status_code || '?'} -> ${currentResponse.status_code || '?'}`} />
        <Metric
          label="Length"
          value={`${previousResponse.content_length ?? 0} -> ${currentResponse.content_length ?? 0}`}
        />
        <Metric
          label="Timing"
          value={`${previousResponse.response_time_ms ?? 0} -> ${currentResponse.response_time_ms ?? 0} ms`}
        />
      </div>
      <div className="diff-lines" aria-label="Response body diff">
        {lines.length === 0 ? (
          <p className="empty-state">Body excerpts are unchanged.</p>
        ) : lines.map((line, index) => (
          <div className={`diff-line diff-${line.kind}`} key={`${line.kind}-${index}-${line.text}`}>
            <span>{line.kind === 'added' ? '+' : line.kind === 'removed' ? '-' : ' '}</span>
            <code>{line.text || ' '}</code>
          </div>
        ))}
      </div>
    </div>
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

function IssuesTable({ findings }) {
  if (!findings.length) {
    return (
      <div className="empty-panel">
        <h3>No issues yet</h3>
        <p>Run or refresh a scan to populate confirmed findings, confidence, affected endpoint, and proof status.</p>
      </div>
    );
  }
  return (
    <div className="issues-table">
      <div className="issues-head">
        <span>Severity</span>
        <span>Issue</span>
        <span>Endpoint</span>
        <span>Confidence</span>
        <span>Proof</span>
      </div>
      {findings.map((finding, index) => (
        <div className="issues-row" key={finding.finding_id || `${finding.type}-${index}`}>
          <span className={`severity-pill severity-${String(finding.severity || 'info').toLowerCase()}`}>{finding.severity || 'info'}</span>
          <strong>{finding.title || finding.type || finding.vuln_type || 'Finding'}</strong>
          <span>{finding.normalized_endpoint || finding.url || finding.target_url || '/'}</span>
          <span>{finding.confidence ?? 0}</span>
          <span>{finding.proof_status || 'not_attempted'}</span>
        </div>
      ))}
    </div>
  );
}

function ProxyControlPanel({
  proxyStatus,
  proxyState,
  pendingProxyRequests,
  refreshProxyStatus,
  startManualProxy,
  stopManualProxy,
  toggleManualProxyIntercept,
  loadProxyPending,
  decideProxyRequest,
}) {
  const [pendingEdits, setPendingEdits] = useState({});
  const running = Boolean(proxyStatus?.running);
  const proxyAddress = running ? `${proxyStatus.host}:${proxyStatus.port}` : 'not listening';

  useEffect(() => {
    setPendingEdits((current) => {
      const next = {};
      pendingProxyRequests.forEach((item) => {
        next[item.request_id] = current[item.request_id] || {
          method: item.method || 'GET',
          url: item.url || '',
          headers: formatKeyValueLines(item.headers || {}),
          body: item.body || item.body_excerpt || '',
        };
      });
      return next;
    });
  }, [pendingProxyRequests]);

  const updateEdit = (requestId, name, value) => {
    setPendingEdits((current) => ({
      ...current,
      [requestId]: {
        ...(current[requestId] || {}),
        [name]: value,
      },
    }));
  };

  const forwardPending = (item) => {
    const edit = pendingEdits[item.request_id] || {};
    decideProxyRequest(item.request_id, 'forward', {
      method: edit.method || item.method,
      url: edit.url || item.url,
      headers: parseKeyValueLines(edit.headers || ''),
      body: edit.body || '',
    });
  };

  return (
    <div className="proxy-control">
      <div className="proxy-control-header">
        <div>
          <span className="eyebrow">Live capture</span>
          <h2>HTTP Proxy</h2>
          <p>Configure your browser HTTP proxy to <strong>{proxyAddress}</strong>. HTTPS CONNECT is intentionally not intercepted yet.</p>
        </div>
        <div className="proxy-actions">
          <button className="secondary-button" onClick={refreshProxyStatus}>Status</button>
          {running ? (
            <button className="secondary-button" onClick={stopManualProxy} disabled={proxyState === 'stopping'}>Stop</button>
          ) : (
            <button className="primary-button" onClick={startManualProxy} disabled={proxyState === 'starting'}>
              {proxyState === 'starting' ? 'Starting' : 'Start proxy'}
            </button>
          )}
        </div>
      </div>
      <div className="proxy-status-grid">
        <Metric label="State" value={running ? 'running' : proxyState} />
        <Metric label="Captured" value={proxyStatus?.captured_count ?? 0} />
        <Metric label="Pending" value={proxyStatus?.pending_count ?? pendingProxyRequests.length} />
        <Metric label="Modified" value={proxyStatus?.modified_count ?? 0} />
      </div>
      <div className="proxy-intercept-row">
        <label>
          <input
            type="checkbox"
            checked={Boolean(proxyStatus?.intercept_enabled)}
            onChange={(event) => toggleManualProxyIntercept(event.target.checked)}
            disabled={!running}
          />
          <span>Pause requests for forward/drop</span>
        </label>
        <button className="secondary-button" onClick={loadProxyPending} disabled={!running}>Load pending</button>
      </div>
      {pendingProxyRequests.length > 0 && (
        <div className="pending-proxy-list">
          {pendingProxyRequests.map((item) => (
            <div className="pending-proxy-card" key={item.request_id}>
              <div className="pending-proxy-row">
                <select
                  value={pendingEdits[item.request_id]?.method || item.method || 'GET'}
                  onChange={(event) => updateEdit(item.request_id, 'method', event.target.value)}
                >
                  {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((method) => (
                    <option key={method} value={method}>{method}</option>
                  ))}
                </select>
                <input
                  value={pendingEdits[item.request_id]?.url || item.url || ''}
                  onChange={(event) => updateEdit(item.request_id, 'url', event.target.value)}
                />
                <button className="secondary-button" onClick={() => decideProxyRequest(item.request_id, 'drop')}>Drop</button>
                <button className="primary-button" onClick={() => forwardPending(item)}>Forward</button>
              </div>
              <div className="pending-proxy-editors">
                <label className="raw-field">
                  <span>Headers</span>
                  <textarea
                    value={pendingEdits[item.request_id]?.headers || ''}
                    onChange={(event) => updateEdit(item.request_id, 'headers', event.target.value)}
                    spellCheck="false"
                  />
                </label>
                <label className="raw-field">
                  <span>Body</span>
                  <textarea
                    value={pendingEdits[item.request_id]?.body || ''}
                    onChange={(event) => updateEdit(item.request_id, 'body', event.target.value)}
                    spellCheck="false"
                  />
                </label>
              </div>
            </div>
          ))}
        </div>
      )}
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

function CorpusViewer({ requests, selectedExchange, onSelect, onSendToRepeater, onSendToIntruder }) {
  return (
    <div className="corpus-viewer">
      <RequestHistory
        requests={requests}
        selectedExchange={selectedExchange}
        onSelect={onSelect}
        onSendToRepeater={onSendToRepeater}
        onSendToIntruder={onSendToIntruder}
      />
      <ExchangeDetail exchange={selectedExchange} />
    </div>
  );
}

function RequestHistory({ requests, selectedExchange, onSelect, onSendToRepeater, onSendToIntruder }) {
  return (
    <div className="request-table" role="table" aria-label="Corpus requests">
      {requests.length === 0 ? (
        <p className="empty-state">No requests loaded.</p>
      ) : requests.map((item) => (
        <div
          className={`request-row ${selectedExchange?.request?.request_id === item.request_id ? 'selected' : ''}`}
          key={item.request_id}
        >
          <button className="request-main" onClick={() => onSelect(item.request_id)}>
            <span className={`method method-${(item.method || 'GET').toLowerCase()}`}>{item.method}</span>
            <span className="request-url">{item.url}</span>
            <span>{item.source}</span>
            <span>{item.auth_role || 'anonymous'}</span>
          </button>
          {onSendToRepeater && (
            <button className="request-repeater-button" onClick={() => onSendToRepeater(item)}>Repeater</button>
          )}
          {onSendToIntruder && (
            <button className="request-repeater-button" onClick={() => onSendToIntruder(item)}>Intruder</button>
          )}
        </div>
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

function DecoderPanel() {
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
    <section id="decoder" className="decoder-panel">
      <div className="section-heading compact">
        <div>
          <span className="eyebrow">Decoder</span>
          <h2>Encode and Decode</h2>
        </div>
      </div>
      <div className="decoder-grid">
        <label className="raw-field">
          <span>Input</span>
          <textarea
            value={input}
            onChange={(event) => {
              setInput(event.target.value);
              setOutput('');
            }}
            spellCheck="false"
          />
        </label>
        <div className="decoder-actions">
          <button className="secondary-button" onClick={() => runTransform('url-decode')}>URL decode</button>
          <button className="secondary-button" onClick={() => runTransform('url-encode')}>URL encode</button>
          <button className="secondary-button" onClick={() => runTransform('base64-decode')}>Base64 decode</button>
          <button className="secondary-button" onClick={() => runTransform('base64-encode')}>Base64 encode</button>
          <button className="secondary-button" onClick={() => runTransform('json-pretty')}>Pretty JSON</button>
          <button className="secondary-button" onClick={() => runTransform('jwt-decode')}>Decode JWT</button>
        </div>
        <label className="raw-field">
          <span>Output</span>
          <textarea value={output} readOnly spellCheck="false" />
        </label>
      </div>
    </section>
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

function manualRequestFromRecord(requestRecord, fallbackRequest, latestScanId) {
  return {
    ...fallbackRequest,
    scanId: requestRecord.scan_id || fallbackRequest.scanId || latestScanId,
    method: requestRecord.method || 'GET',
    url: requestRecord.url || fallbackRequest.url,
    headers: formatKeyValueLines(requestRecord.headers || {}),
    body: stringifyBody(requestRecord.body),
  };
}

function buildIntruderRequest(baseRequest, marker, payload) {
  const token = marker || '{{payload}}';
  const next = {
    ...baseRequest,
    url: replacePayloadMarker(baseRequest.url, token, payload),
    headers: replacePayloadMarker(baseRequest.headers, token, payload),
    body: replacePayloadMarker(baseRequest.body, token, payload),
  };
  const markerWasPresent = [baseRequest.url, baseRequest.headers, baseRequest.body]
    .some((value) => String(value || '').includes(token));
  if (!markerWasPresent) {
    next.url = appendPayloadParam(baseRequest.url, payload);
  }
  return next;
}

function replacePayloadMarker(value, marker, payload) {
  return String(value || '').split(marker).join(payload);
}

function appendPayloadParam(url, payload) {
  try {
    const parsed = new URL(String(url || ''));
    parsed.searchParams.set('wraith_payload', payload);
    return parsed.toString();
  } catch (_error) {
    return url;
  }
}

function buildIntruderResult(payload, request, response) {
  const status = response?.status_code || 'error';
  const length = Number(response?.content_length || 0);
  const timeMs = Number(response?.response_time_ms || 0);
  return {
    resultId: `intr_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`,
    payload,
    status,
    length,
    timeMs,
    cluster: `${status}:${length}:${response?.body_hash || ''}`.slice(0, 80),
    exchange: { request, response },
  };
}

function buildIntruderError(payload, error) {
  return {
    resultId: `intr_err_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`,
    payload,
    status: 'error',
    length: 0,
    timeMs: 0,
    cluster: 'error',
    error: error?.response?.data?.error || error.message,
  };
}

function summarizeIntruderResults(results) {
  const clusters = new Set(results.map((item) => item.cluster).filter(Boolean));
  return {
    clusters: clusters.size,
    errors: results.filter((item) => item.status === 'error').length,
  };
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function formatKeyValueLines(value) {
  return Object.entries(value || {})
    .map(([key, val]) => `${key}: ${val}`)
    .join('\n');
}

function repeaterTitle(request) {
  try {
    const parsed = new URL(request.url || '');
    return `${request.method || 'GET'} ${parsed.pathname || '/'}`;
  } catch (_error) {
    return `${request.method || 'GET'} request`;
  }
}

function buildRepeaterAttempt(request, response) {
  const attemptId = `attempt_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`;
  const status = response?.status_code || 'error';
  const endpoint = request?.normalized_endpoint || safePath(request?.url) || '/';
  return {
    attemptId,
    label: `${request?.method || 'GET'} ${endpoint}`,
    timestamp: new Date().toISOString(),
    exchange: { request, response },
    status,
  };
}

function selectedRepeaterAttempt(tab) {
  const attempts = tab?.attempts || [];
  return attempts.find((item) => item.attemptId === tab?.activeAttemptId) || attempts[0] || null;
}

function attemptDelta(attempt, previous) {
  if (!previous) return 'baseline';
  const currentResponse = attempt.exchange?.response || {};
  const previousResponse = previous.exchange?.response || {};
  const parts = [];
  if (currentResponse.status_code !== previousResponse.status_code) {
    parts.push(`${previousResponse.status_code || '?'}->${currentResponse.status_code || '?'}`);
  }
  const lengthDelta = Number(currentResponse.content_length || 0) - Number(previousResponse.content_length || 0);
  if (lengthDelta) parts.push(`${lengthDelta > 0 ? '+' : ''}${lengthDelta} B`);
  const timeDelta = Number(currentResponse.response_time_ms || 0) - Number(previousResponse.response_time_ms || 0);
  if (timeDelta) parts.push(`${timeDelta > 0 ? '+' : ''}${timeDelta} ms`);
  return parts.join(', ') || 'same';
}

function buildSimpleDiff(beforeValue, afterValue) {
  const before = normalizeDiffText(beforeValue);
  const after = normalizeDiffText(afterValue);
  if (before === after) return [];
  const beforeLines = before.split(/\r?\n/).slice(0, 80);
  const afterLines = after.split(/\r?\n/).slice(0, 80);
  const rows = [];
  const max = Math.max(beforeLines.length, afterLines.length);
  for (let index = 0; index < max; index += 1) {
    const previous = beforeLines[index];
    const current = afterLines[index];
    if (previous === current) {
      if (previous !== undefined && rows.length < 40) rows.push({ kind: 'same', text: previous });
      continue;
    }
    if (previous !== undefined) rows.push({ kind: 'removed', text: previous });
    if (current !== undefined) rows.push({ kind: 'added', text: current });
    if (rows.length >= 80) break;
  }
  return rows.slice(0, 80);
}

function normalizeDiffText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function safePath(value) {
  try {
    return new URL(String(value || '')).pathname || '/';
  } catch (_error) {
    return '/';
  }
}

function stringifyBody(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function safeOrigin(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.origin;
    }
  } catch (_error) {
    return '';
  }
  return '';
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
