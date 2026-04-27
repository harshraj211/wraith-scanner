import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import './App.css';

import AppShell from './components/layout/AppShell';
import Overview from './pages/Overview';
import ModeSelect from './pages/ModeSelect';
import AutomatedScanSetup from './pages/AutomatedScanSetup';
import AutomatedWorkspace from './pages/AutomatedWorkspace';
import Findings from './pages/Findings';
import EvidenceCorpus from './pages/EvidenceCorpus';
import ManualTesting from './pages/ManualTesting';
import ProxyHistory from './pages/ProxyHistory';
import Repeater from './pages/Repeater';
import Intruder from './pages/Intruder';
import Decoder from './pages/Decoder';
import RepositoryScan from './pages/RepositoryScan';
import ProofMode from './pages/ProofMode';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:5001';

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

const hashToPage = {
  '#': 'overview',
  '#overview': 'overview',
  '#home': 'overview',
  '#start': 'mode',
  '#mode': 'mode',
  '#automated': 'automated-workspace',
  '#result-dashboard': 'automated-workspace',
  '#automated-workspace': 'automated-workspace',
  '#scan-setup': 'automated-setup',
  '#scan-details': 'automated-setup',
  '#automated-setup': 'automated-setup',
  '#issues': 'findings',
  '#findings': 'findings',
  '#traffic-corpus': 'evidence',
  '#evidence': 'evidence',
  '#manual': 'manual',
  '#manual-testing': 'manual',
  '#proxy-history': 'proxy',
  '#proxy': 'proxy',
  '#replay': 'repeater',
  '#repeater': 'repeater',
  '#intruder': 'intruder',
  '#decoder': 'decoder',
  '#repository': 'repository',
  '#repository-scan': 'repository',
  '#proof': 'proof',
  '#proof-mode': 'proof',
  '#reports': 'reports',
  '#reporting': 'reports',
  '#terminal': 'reports',
  '#settings': 'settings',
};

const pageToHash = {
  overview: '#overview',
  mode: '#start',
  'automated-setup': '#scan-setup',
  'automated-workspace': '#result-dashboard',
  findings: '#issues',
  evidence: '#traffic-corpus',
  manual: '#manual',
  proxy: '#proxy-history',
  repeater: '#replay',
  intruder: '#intruder',
  decoder: '#decoder',
  repository: '#repository-scan',
  proof: '#proof-mode',
  reports: '#reports',
  settings: '#settings',
};

function pageFromLocation() {
  const hash = String(window.location.hash || '#overview').toLowerCase();
  return hashToPage[hash] || 'overview';
}

function App() {
  const intruderAbortRef = useRef(false);
  const [activePage, setActivePage] = useState(pageFromLocation);
  const [socketState, setSocketState] = useState('connecting');
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
  const [repoForm, setRepoForm] = useState({ url: '', token: '', branch: 'main' });
  const [repoState, setRepoState] = useState('idle');
  const [proofState, setProofState] = useState('safe mode');

  const addProgress = useCallback((event) => {
    const item = {
      timestamp: event.timestamp || new Date().toISOString(),
      type: event.type || event.status || 'info',
      message: event.message || event.detail || 'event',
      scan_id: event.scan_id || latestScanId,
    };
    setProgressEvents((current) => [item, ...current].slice(0, 250));
  }, [latestScanId]);

  const navigate = useCallback((page) => {
    const normalized = page || 'overview';
    setActivePage(normalized);
    const hash = pageToHash[normalized] || '#overview';
    if (window.location.hash !== hash) {
      window.history.replaceState(null, '', `${window.location.pathname}${hash}`);
    }
  }, []);

  useEffect(() => {
    const onHashChange = () => setActivePage(pageFromLocation());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    const socket = typeof io === 'function' ? io(API_URL, { transports: ['websocket', 'polling'] }) : null;
    if (!socket || typeof socket.on !== 'function') {
      setSocketState('offline');
      return undefined;
    }
    socket.on('connect', () => setSocketState('connected'));
    socket.on('disconnect', () => setSocketState('disconnected'));
    socket.on('connect_error', () => setSocketState('disconnected'));
    socket.on('scan_progress', (event) => {
      addProgress(event || {});
      if (event?.scan_id) setLatestScanId(event.scan_id);
      if (['completed', 'complete', 'error', 'failed'].includes(String(event?.status || event?.type || '').toLowerCase())) {
        setTimeout(() => refreshStatus(event.scan_id), 300);
      }
    });
    return () => socket.disconnect?.();
    // Socket setup intentionally depends only on progress writer to avoid reconnecting
    // when scan status state changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [addProgress]);

  const scanPayload = useMemo(() => buildScanPayload(form), [form]);
  const findings = useMemo(() => normalizeFindings(scanStatus), [scanStatus]);
  const dashboard = useMemo(
    () => buildDashboard(scanStatus, corpusRequests, progressEvents, scanPayload, findings),
    [scanStatus, corpusRequests, progressEvents, scanPayload, findings],
  );
  const selectedIntruderResult = useMemo(
    () => intruderResults.find((result) => result.resultId === selectedIntruderResultId) || intruderResults[intruderResults.length - 1] || null,
    [intruderResults, selectedIntruderResultId],
  );

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

  const updateRepoForm = (name, value) => {
    setRepoForm((current) => ({ ...current, [name]: value }));
  };

  const submitScan = async (event) => {
    if (event?.preventDefault) event.preventDefault();
    if (!scanPayload.url) return;
    setLaunchState('starting');
    setScanStatus(null);
    navigate('automated-workspace');
    try {
      const response = await axios.post(`${API_URL}/api/scan`, scanPayload);
      const scanId = response.data.scan_id;
      setLatestScanId(scanId);
      applyManualRequestUpdate((current) => ({ ...current, scanId }));
      addProgress({ scan_id: scanId, type: 'success', message: `Scan started: ${scanId}` });
      setLaunchState('started');
      setTimeout(() => refreshStatus(scanId), 700);
    } catch (error) {
      setLaunchState('error');
      addProgress({ type: 'error', message: apiError(error) });
    }
  };

  const refreshStatus = async (scanId = latestScanId) => {
    if (!scanId) return;
    try {
      const response = await axios.get(`${API_URL}/api/scan/${scanId}`);
      setScanStatus(response.data);
      if (response.data?.scan_id) setLatestScanId(response.data.scan_id);
    } catch (error) {
      addProgress({ scan_id: scanId, type: 'error', message: apiError(error) });
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
      if (requests.length > 0) loadExchange(requests[0].request_id);
      else setSelectedExchange(null);
    } catch (error) {
      setCorpusState('error');
      addProgress({ scan_id: scanId, type: 'error', message: apiError(error) });
    }
  };

  const loadExchange = async (requestId) => {
    if (!requestId) return;
    try {
      const response = await axios.get(`${API_URL}/api/corpus/request/${requestId}`);
      setSelectedExchange(response.data);
    } catch (error) {
      addProgress({ scan_id: latestScanId, type: 'error', message: apiError(error) });
    }
  };

  const updateCorpusFilter = (name, value) => {
    setCorpusFilters((current) => ({ ...current, [name]: value }));
  };

  const selectRepeaterTab = (tabId) => {
    const tab = repeaterTabs.find((item) => item.tabId === tabId);
    if (!tab) return;
    setActiveRepeaterTabId(tabId);
    setManualRequest(tab.request);
    const activeAttempt = selectedRepeaterAttempt(tab);
    setSelectedExchange(activeAttempt?.exchange || null);
    navigate('repeater');
  };

  const createRepeaterTab = () => {
    const request = { ...initialManualRequest, scanId: manualRequest.scanId || latestScanId };
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
    navigate('repeater');
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

  const submitRepoScan = async () => {
    if (!repoForm.url.trim()) return;
    setRepoState('scanning');
    try {
      const payload = { url: repoForm.url.trim() };
      if (repoForm.token.trim()) payload.token = repoForm.token.trim();
      if (repoForm.branch.trim()) payload.branch = repoForm.branch.trim();
      const response = await axios.post(`${API_URL}/api/scan/repo`, payload);
      const scanId = response.data.scan_id;
      setLatestScanId(scanId);
      setRepoState('started');
      addProgress({ scan_id: scanId, type: 'success', message: `Repository scan started: ${scanId}` });
    } catch (error) {
      setRepoState('error');
      addProgress({ type: 'error', message: apiError(error) });
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
        source: 'manual',
      });
      const scanId = response.data.scan_id;
      const exchange = { request: response.data.request, response: response.data.response };
      const attempt = buildRepeaterAttempt(response.data.request, response.data.response);
      setManualState('sent');
      setLatestScanId(scanId);
      setSelectedExchange(exchange);
      applyManualRequestUpdate((current) => ({ ...current, scanId }));
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
      addProgress({ scan_id: scanId, type: 'success', message: `Manual replay captured: ${response.data.request?.method || ''} ${response.data.request?.url || ''}` });
    } catch (error) {
      setManualState('error');
      addProgress({ scan_id: manualRequest.scanId || latestScanId, type: 'error', message: apiError(error) });
    }
  };

  const refreshProxyStatus = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/manual/proxy/status`);
      setProxyStatus(response.data || { running: false });
      setProxyState(response.data?.running ? 'running' : 'idle');
    } catch (error) {
      addProgress({ type: 'error', message: apiError(error) });
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
      addProgress({ scan_id: status.scan_id, type: 'success', message: `Manual proxy listening on ${status.host}:${status.port}` });
    } catch (error) {
      setProxyState('error');
      addProgress({ scan_id: manualRequest.scanId || latestScanId, type: 'error', message: apiError(error) });
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
      addProgress({ type: 'error', message: apiError(error) });
    }
  };

  const toggleManualProxyIntercept = async (enabled) => {
    try {
      const response = await axios.post(`${API_URL}/api/manual/proxy/intercept`, { enabled });
      setProxyStatus(response.data || { running: false });
    } catch (error) {
      addProgress({ type: 'error', message: apiError(error) });
    }
  };

  const loadProxyPending = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/manual/proxy/pending`);
      setPendingProxyRequests(response.data.requests || []);
    } catch (error) {
      addProgress({ type: 'error', message: apiError(error) });
    }
  };

  const decideProxyRequest = async (requestId, action, requestUpdate) => {
    try {
      const payload = { action };
      if (requestUpdate) payload.request = requestUpdate;
      await axios.post(`${API_URL}/api/manual/proxy/pending/${requestId}`, payload);
      await loadProxyPending();
      if (action === 'forward') setTimeout(() => loadCorpus(manualRequest.scanId || latestScanId), 300);
    } catch (error) {
      addProgress({ type: 'error', message: apiError(error) });
    }
  };

  const sendRequestToRepeater = (requestRecord) => {
    if (!requestRecord) return;
    const nextRequest = manualRequestFromRecord(requestRecord, manualRequest, latestScanId);
    const sourceRequestId = requestRecord.request_id || '';
    const existingTab = repeaterTabs.find((tab) => tab.sourceRequestId && tab.sourceRequestId === sourceRequestId);
    if (existingTab) {
      setRepeaterTabs((current) => current.map((tab) => (
        tab.tabId === existingTab.tabId ? { ...tab, title: repeaterTitle(nextRequest), request: nextRequest } : tab
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
    navigate('repeater');
  };

  const sendRequestToIntruder = (requestRecord) => {
    if (!requestRecord) return;
    const nextRequest = manualRequestFromRecord(requestRecord, manualRequest, latestScanId);
    setManualRequest(nextRequest);
    navigate('intruder');
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

  const createProofTask = async (finding) => {
    if (!finding?.finding_id) return null;
    setProofState('creating');
    try {
      const response = await axios.post(`${API_URL}/api/proof/${finding.finding_id}/task`, {
        safety_mode: 'safe',
      });
      setProofState('created');
      addProgress({ type: 'success', message: `Proof task created for ${finding.title || finding.finding_id}` });
      return response.data;
    } catch (error) {
      setProofState('error');
      addProgress({ type: 'error', message: apiError(error) });
      return null;
    }
  };

  const runProofTask = async (finding) => {
    const task = await createProofTask(finding);
    const taskId = task?.task_id || task?.task?.task_id;
    if (!taskId) return;
    setProofState('running');
    try {
      const response = await axios.post(`${API_URL}/api/proof/${taskId}/run`);
      setProofState(response.data?.status || 'complete');
      addProgress({ type: 'success', message: `Proof task completed: ${taskId}` });
      if (latestScanId) loadCorpus(latestScanId);
    } catch (error) {
      setProofState('error');
      addProgress({ type: 'error', message: apiError(error) });
    }
  };

  const downloadPdf = () => {
    if (latestScanId) window.open(`${API_URL}/api/download/${latestScanId}`, '_blank');
  };

  const downloadJson = () => {
    if (latestScanId) window.open(`${API_URL}/api/download-json/${latestScanId}`, '_blank');
  };

  const renderPage = () => {
    switch (activePage) {
      case 'mode':
        return <ModeSelect onNavigate={navigate} />;
      case 'automated-setup':
        return <AutomatedScanSetup form={form} updateForm={updateForm} submitScan={submitScan} launchState={launchState} onNavigate={navigate} />;
      case 'automated-workspace':
        return (
          <AutomatedWorkspace
            scanStatus={scanStatus}
            latestScanId={latestScanId}
            dashboard={dashboard}
            progressEvents={progressEvents}
            corpusRequests={corpusRequests}
            refreshStatus={() => refreshStatus(latestScanId)}
            submitScan={submitScan}
            onNavigate={navigate}
          />
        );
      case 'findings':
        return <Findings findings={findings} onNavigate={navigate} onRunProof={runProofTask} />;
      case 'evidence':
        return (
          <EvidenceCorpus
            latestScanId={latestScanId}
            corpusRequests={corpusRequests}
            selectedExchange={selectedExchange}
            corpusFilters={corpusFilters}
            updateCorpusFilter={updateCorpusFilter}
            loadCorpus={loadCorpus}
            loadExchange={loadExchange}
            sendRequestToRepeater={sendRequestToRepeater}
            sendRequestToIntruder={sendRequestToIntruder}
          />
        );
      case 'manual':
        return <ManualTesting onNavigate={navigate} proxyStatus={proxyStatus} corpusRequests={corpusRequests} />;
      case 'proxy':
        return (
          <ProxyHistory
            latestScanId={latestScanId}
            proxyStatus={proxyStatus}
            proxyState={proxyState}
            pendingProxyRequests={pendingProxyRequests}
            startManualProxy={startManualProxy}
            stopManualProxy={stopManualProxy}
            refreshProxyStatus={refreshProxyStatus}
            toggleManualProxyIntercept={toggleManualProxyIntercept}
            loadProxyPending={loadProxyPending}
            decideProxyRequest={decideProxyRequest}
            corpusRequests={corpusRequests}
            selectedExchange={selectedExchange}
            loadExchange={loadExchange}
            sendRequestToRepeater={sendRequestToRepeater}
            sendRequestToIntruder={sendRequestToIntruder}
          />
        );
      case 'repeater':
        return (
          <Repeater
            manualRequest={manualRequest}
            updateManualRequest={updateManualRequest}
            sendManualReplay={sendManualReplay}
            manualState={manualState}
            repeaterTabs={repeaterTabs}
            activeRepeaterTabId={activeRepeaterTabId}
            selectRepeaterTab={selectRepeaterTab}
            createRepeaterTab={createRepeaterTab}
            closeRepeaterTab={closeRepeaterTab}
            selectedExchange={selectedExchange}
            onNavigate={navigate}
          />
        );
      case 'intruder':
        return (
          <Intruder
            manualRequest={manualRequest}
            updateManualRequest={updateManualRequest}
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
          />
        );
      case 'decoder':
        return <Decoder />;
      case 'repository':
        return <RepositoryScan repoForm={repoForm} updateRepoForm={updateRepoForm} submitRepoScan={submitRepoScan} repoState={repoState} progressEvents={progressEvents} />;
      case 'proof':
        return <ProofMode findings={findings} proofState={proofState} onCreateProof={createProofTask} onRunProof={runProofTask} corpusRequests={corpusRequests} loadExchange={loadExchange} />;
      case 'reports':
        return <Reports latestScanId={latestScanId} progressEvents={progressEvents} onDownloadPdf={downloadPdf} onDownloadJson={downloadJson} />;
      case 'settings':
        return <Settings />;
      case 'overview':
      default:
        return <Overview onNavigate={navigate} stats={{ scanId: latestScanId, requests: corpusRequests.length }} />;
    }
  };

  return (
    <AppShell
      activePage={activePage}
      onNavigate={navigate}
      socketState={socketState}
      latestScanId={latestScanId}
      onStartScan={() => navigate('mode')}
    >
      {renderPage()}
      <span className="sr-only" aria-live="polite">{corpusState}</span>
    </AppShell>
  );
}

function normalizeFindings(status) {
  const raw = status?.canonical_findings || status?.findings || status?.results?.findings || [];
  if (!Array.isArray(raw)) return [];
  return raw.map((finding, index) => ({
    finding_id: finding.finding_id || finding.id || `finding-${index}`,
    title: finding.title || finding.name || finding.vulnerability || finding.vuln_type || 'Finding',
    severity: finding.severity || finding.risk || 'info',
    confidence: finding.confidence ?? finding.confidence_score ?? '',
    target_url: finding.target_url || finding.url || status?.target || '',
    normalized_endpoint: finding.normalized_endpoint || finding.endpoint || finding.path || '',
    method: finding.method || '',
    parameter_name: finding.parameter_name || finding.parameter || finding.param || '',
    proof_status: finding.proof_status || 'not_attempted',
    cwe: finding.cwe || '',
    remediation: finding.remediation || '',
    discovery_evidence: finding.discovery_evidence || finding.evidence || finding.description || '',
    ...finding,
  }));
}

function buildDashboard(status, requests, events, scanPayload, findings) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    const severity = String(finding.severity || 'info').toLowerCase();
    if (severityCounts[severity] !== undefined) severityCounts[severity] += 1;
    else severityCounts.info += 1;
  });
  const totalFindings = status?.total_vulnerabilities ?? findings.length;
  const confirmedFindings = findings.filter((finding) => (
    ['succeeded', 'partial', 'verified'].includes(String(finding.proof_status || '').toLowerCase())
    || Number(finding.confidence || 0) >= 85
  )).length;
  return {
    totalFindings,
    confirmed: confirmedFindings,
    confirmedFindings,
    requestCount: requests.length,
    importCount: countImports(status?.api_imports || scanPayload.imports),
    severityCounts,
    timeline: buildTimeline(events, totalFindings),
  };
}

function buildTimeline(events, totalFindings) {
  if (!events.length) return [0, 0, 0, 0, totalFindings || 0];
  const points = [];
  let current = 0;
  events.slice().reverse().forEach((event) => {
    if (['success', 'warning', 'phase', 'finding'].includes(event.type)) current += 1;
    points.push(current);
  });
  if (totalFindings && points.length) points[points.length - 1] = totalFindings;
  return points.slice(-8);
}

function buildScanPayload(form) {
  const payload = { url: form.targetUrl.trim() };
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

function formatKeyValueLines(value) {
  return Object.entries(value || {}).map(([key, val]) => `${key}: ${val}`).join('\n');
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

function repeaterTitle(request) {
  try {
    const parsed = new URL(request.url || '');
    return `${request.method || 'GET'} ${parsed.pathname || '/'}`;
  } catch (_error) {
    return `${request.method || 'GET'} request`;
  }
}

function selectedRepeaterAttempt(tab) {
  const attempts = tab?.attempts || [];
  return attempts.find((item) => item.attemptId === tab?.activeAttemptId) || attempts[0] || null;
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

function buildIntruderRequest(baseRequest, marker, payload) {
  const token = marker || '{{payload}}';
  const next = {
    ...baseRequest,
    url: replacePayloadMarker(baseRequest.url, token, payload),
    headers: replacePayloadMarker(baseRequest.headers, token, payload),
    body: replacePayloadMarker(baseRequest.body, token, payload),
  };
  const markerWasPresent = [baseRequest.url, baseRequest.headers, baseRequest.body].some((value) => String(value || '').includes(token));
  if (!markerWasPresent) next.url = appendPayloadParam(baseRequest.url, payload);
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
    error: apiError(error),
  };
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

function safePath(value) {
  try {
    return new URL(String(value || '')).pathname || '/';
  } catch (_error) {
    return '/';
  }
}

function safeOrigin(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.origin;
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

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function apiError(error) {
  return error?.response?.data?.error || error?.response?.data?.message || error.message || 'Request failed';
}

export default App;
