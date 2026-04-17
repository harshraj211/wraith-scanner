import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import io from 'socket.io-client';
import axios from 'axios';
import 'xterm/css/xterm.css';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:5001';

// ─────────────────────────────────────────────
// ANSI color helpers — real escape chars, never raw \x1b strings
// ─────────────────────────────────────────────
const ESC = String.fromCharCode(27);
const RESET = ESC + '[0m';
const c = (code, text) => `${ESC}[${code}m${text}${RESET}`;

// Pre-built color codes for VULN_META
const RED    = ESC + '[1;31m';
const YELLOW = ESC + '[1;33m';
const DIM_YL = ESC + '[0;33m';
const DIM    = ESC + '[0;37m';

// ─────────────────────────────────────────────
// Vulnerability type → display metadata
// ─────────────────────────────────────────────
const VULN_META = {
  // A01 – Broken Access Control
  'idor':                       { label: 'IDOR',              color: YELLOW, owasp: 'A01' },
  'open-redirect':              { label: 'OPEN REDIRECT',     color: YELLOW, owasp: 'A01' },
  'csrf':                       { label: 'CSRF',              color: YELLOW, owasp: 'A01' },

  // A02 – Cryptographic Failures
  'crypto-plaintext-http':      { label: 'PLAINTEXT HTTP',    color: RED,    owasp: 'A02' },
  'crypto-missing-hsts':        { label: 'MISSING HSTS',      color: RED,    owasp: 'A02' },
  'crypto-weak-hsts':           { label: 'WEAK HSTS',         color: DIM_YL, owasp: 'A02' },
  'crypto-insecure-cookie':     { label: 'INSECURE COOKIE',   color: YELLOW, owasp: 'A02' },
  'crypto-sensitive-data-exposure': { label: 'DATA EXPOSURE', color: RED,    owasp: 'A02' },
  'crypto-mixed-content':       { label: 'MIXED CONTENT',     color: DIM_YL, owasp: 'A02' },
  'crypto-weak-tls-version':    { label: 'WEAK TLS',          color: RED,    owasp: 'A02' },
  'crypto-weak-cipher':         { label: 'WEAK CIPHER',       color: RED,    owasp: 'A02' },
  'crypto-invalid-certificate': { label: 'INVALID CERT',      color: RED,    owasp: 'A02' },
  'crypto-no-https-redirect':   { label: 'NO HTTPS REDIRECT', color: YELLOW, owasp: 'A02' },
  'crypto-http-form-submission':{ label: 'HTTP FORM POST',    color: RED,    owasp: 'A02' },

  // A03 – Injection
  'error-based':                { label: 'SQLi (ERROR)',      color: RED,    owasp: 'A03' },
  'sqli-error':                 { label: 'SQLi (ERROR)',      color: RED,    owasp: 'A03' },
  'sqli-boolean-blind':         { label: 'SQLi (BOOLEAN)',    color: RED,    owasp: 'A03' },
  'sqli-time-blind':            { label: 'SQLi (TIME)',       color: RED,    owasp: 'A03' },
  'sqli-oob':                   { label: 'SQLi (OOB)',        color: RED,    owasp: 'A03' },
  'sqli-waf-bypass':            { label: 'SQLi (BYPASS)',     color: RED,    owasp: 'A03' },
  'sqli-time-blind-waf-bypass': { label: 'SQLi (TIME BYPASS)',color: RED,    owasp: 'A03' },
  'time-based':                 { label: 'SQLi (TIME)',       color: RED,    owasp: 'A03' },
  'reflected-xss':              { label: 'XSS (REFLECTED)',  color: RED,    owasp: 'A03' },
  'xss-reflected':              { label: 'XSS (REFLECTED)',   color: RED,    owasp: 'A03' },
  'xss-dom':                    { label: 'XSS (DOM)',         color: RED,    owasp: 'A03' },
  'xss-stored':                 { label: 'XSS (STORED)',      color: RED,    owasp: 'A03' },
  'command-injection':          { label: 'CMD INJECTION',    color: RED,    owasp: 'A03' },
  'xxe':                        { label: 'XXE',              color: RED,    owasp: 'A03' },
  'ssti':                       { label: 'SSTI',             color: RED,    owasp: 'A03' },

  // A05 – Security Misconfiguration
  'header-missing':             { label: 'MISSING HEADER',   color: DIM_YL, owasp: 'A05' },
  'header-info-disclosure':     { label: 'HEADER LEAK',      color: DIM_YL, owasp: 'A05' },
  'header-weak-csp':            { label: 'WEAK CSP',         color: YELLOW, owasp: 'A05' },
  'header-cors-wildcard':       { label: 'CORS WILDCARD',    color: YELLOW, owasp: 'A05' },
  'header-cors-reflect-origin': { label: 'CORS REFLECT',     color: RED,    owasp: 'A05' },

  // A06 – Vulnerable Components
  'vulnerable-component':       { label: 'VULN COMPONENT',   color: YELLOW, owasp: 'A06' },

  // A05 / WordPress
  'wordpress-xmlrpc':           { label: 'WP XML-RPC',       color: DIM_YL, owasp: 'A05' },
  'wordpress-info-disclosure':  { label: 'WP INFO LEAK',     color: DIM_YL, owasp: 'A05' },
  'wordpress-user-enum':        { label: 'WP USER ENUM',     color: DIM_YL, owasp: 'A05' },
  'wordpress-directory-listing':{ label: 'WP DIR LISTING',   color: DIM_YL, owasp: 'A05' },

  // A08 / Path Traversal
  'path-traversal':             { label: 'PATH TRAVERSAL',   color: RED,    owasp: 'A08' },

  // A10 – SSRF
  'ssrf':                       { label: 'SSRF',             color: RED,    owasp: 'A10' },
  'blind-ssrf':                 { label: 'SSRF (OOB)',       color: RED,    owasp: 'A10' },

};

const OWASP_LABELS = {
  'A01': c('38;5;208', '[A01-ACCESS]'),
  'A02': c('38;5;196', '[A02-CRYPTO]'),
  'A03': c('38;5;196', '[A03-INJECT]'),
  'A05': c('38;5;220', '[A05-CONFIG]'),
  'A06': c('38;5;208', '[A06-COMPON]'),
  'A08': c('38;5;196', '[A08-INTEGR]'),
  'A10': c('38;5;196', '[A10-SSRF]'),

};

function getVulnDisplay(type) {
  const ltype = (type || '').toLowerCase();
  // Exact match first
  if (VULN_META[ltype]) return VULN_META[ltype];
  // Prefix match
  for (const key of Object.keys(VULN_META)) {
    if (ltype.startsWith(key) || ltype.includes(key)) return VULN_META[key];
  }
  return { label: type.toUpperCase(), color: '\x1b[0;37m', owasp: '???' };
}

function App() {
  const terminalRef = useRef(null);
  const termRef = useRef(null);
  const [terminal, setTerminal] = useState(null);


  // ─── Terminal init ───
  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: '"Fira Code", "Cascadia Code", "JetBrains Mono", Consolas, monospace',
      theme: {
        background:    '#0a0e14',
        foreground:    '#b3b1ad',
        cursor:        '#e6b450',
        cursorAccent:  '#0a0e14',
        black:         '#0a0e14',
        red:           '#ff3333',
        green:         '#c2d94c',
        yellow:        '#e6b450',
        blue:          '#59c2ff',
        magenta:       '#d2a6ff',
        cyan:          '#95e6cb',
        white:         '#b3b1ad',
        brightBlack:   '#404040',
        brightRed:     '#ff6666',
        brightGreen:   '#d2e580',
        brightYellow:  '#ffcc66',
        brightBlue:    '#80d4ff',
        brightMagenta: '#e0c0ff',
        brightCyan:    '#b8f0de',
        brightWhite:   '#ffffff',
      },
      lineHeight: 1.3,
      scrollback: 5000,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);
    term.open(terminalRef.current);
    fitAddon.fit();
    termRef.current = term;

    printBanner(term);
    printPrompt(term);
    setTerminal(term);

    // WebSocket
    const ws = io(API_URL);
    ws.on('connect', () => {
      term.writeln(c('0;90', '[ws] connected to api server'));
    });

    ws.on('scan_progress', ({ message, type }) => {
      const line = formatProgressLine(message, type);
      term.writeln(line);
    });

    ws.on('disconnect', () => {
      term.writeln(c('1;31', '[ws] connection lost'));
    });

    ws.on('connect_error', () => {
      term.writeln(c('1;31', `[ws] unable to reach api server at ${API_URL}`));
    });

    const handleResize = () => fitAddon.fit();
    window.addEventListener('resize', handleResize);

    return () => {
      term.dispose();
      ws.disconnect();
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  // ─── Input handler ───
  useEffect(() => {
    if (!terminal) return;
    let line = '';

    const disposable = terminal.onData(async (data) => {
      const code = data.charCodeAt(0);
      if (code === 13) {
        terminal.writeln('');
        const cmd = line.trim();
        if (cmd) await executeCommand(cmd, terminal);
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
  }, [terminal]);

  return (
    <div className="App">
      <div className="titlebar">
        <div className="titlebar-dots">
          <span className="dot dot-red" />
          <span className="dot dot-yellow" />
          <span className="dot dot-green" />
        </div>
        <span className="titlebar-title">wraith — terminal</span>

      </div>
      <div ref={terminalRef} className="terminal-container" />
    </div>
  );
}

// ─────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────
function printBanner(term) {
  const w = (str) => term.writeln(str);
  const div = c('0;90', ' ' + '─'.repeat(73));

  w('');
  w(c('38;5;196', ' ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗'));
  w(c('38;5;202', ' ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║'));
  w(c('38;5;208', ' ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║'));
  w(c('38;5;214', ' ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║'));
  w(c('38;5;220', ' ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║'));
  w(c('38;5;226', '  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝'));
  w('');
  w(div);
  w(
    c('0;37', '  Web Vulnerability Scanner') +
    c('38;5;240', '  │') +
    c('0;37', '  OWASP Top 10 Coverage') +
    c('38;5;240', '  │') +
    c('38;5;220', '  v4.0')
  );
  w(div);
  w('');
  w(c('38;5;220', ' OWASP Coverage:'));

  const owaspRows = [
    ['A01', 'Broken Access Control',      'IDOR · CSRF · Open Redirect'],
    ['A02', 'Cryptographic Failures',     'TLS · HSTS · Cookies · Data Exposure'],
    ['A03', 'Injection',                  'SQLi · XSS · CMDi · XXE · SSTI'],
    ['A05', 'Security Misconfiguration',  'Headers · CORS · CSP · WordPress'],
    ['A06', 'Vulnerable Components',      'Library CVEs · Version Disclosure'],
    ['A08', 'Software & Data Integrity',  'Path Traversal'],
    ['A10', 'SSRF',                       'Internal · Cloud Metadata · LAN'],
  ];

  owaspRows.forEach(([code, name, items]) => {
    const codeClr = (code === 'A02' || code === 'A03' || code === 'A10') ? '38;5;196' : '38;5;208';
    w(
      '  ' + c(codeClr, code) +
      c('0;90', ' │') +
      c('0;37', ' ' + name.padEnd(32)) +
      c('0;90', items)
    );
  });

  w('');
  w(div);
  w(
    c('38;5;245', '  Commands: ') +
    c('38;5;220', 'scan') + c('38;5;245', ' <url>  ') +
    c('38;5;220', 'scanrepo') + c('38;5;245', ' <url>  ') +
    c('38;5;220', 'status') + c('38;5;245', ' <id>  ') +
    c('38;5;220', 'download') + c('38;5;245', ' <id>  ') +
    c('38;5;220', 'help') + c('38;5;245', '  ') +
    c('38;5;220', 'clear')
  );
  w(c('38;5;240', '  Engines: intelligent payload mutation  │  deep-state SPA  │  cross-file taint  │  OOB mapping'));
  w('');
}

// ─────────────────────────────────────────────
// Prompt
// ─────────────────────────────────────────────
function printPrompt(term) {
  term.write(
    c('38;5;196', '┌──(') +
    c('38;5;208', 'scanner') +
    c('38;5;196', ')-[') +
    c('38;5;220', '~') +
    c('38;5;196', ']') +
    '\r\n' +
    c('38;5;196', '└─$') +
    ' '
  );
}

// ─────────────────────────────────────────────
// Progress line formatter
// ─────────────────────────────────────────────
function formatProgressLine(message, type) {
  const vulnMatch = message.match(/Found (.+?) in ['"](.+?)['"]/i)
                 || message.match(/Found (.+?)$/i);

  if (type === 'warning' && vulnMatch) {
    const rawType = vulnMatch[1] || '';
    const meta = getVulnDisplay(rawType);
    const owaspTag = OWASP_LABELS[meta.owasp] || '';
    return (
      '  ' + meta.color + '[VULN] ' + meta.label.padEnd(20) + RESET +
      ' ' + owaspTag +
      ' ' + c('0;90', message)
    );
  }

  switch (type) {
    case 'phase':
      return '\r\n' + c('38;5;245', ' ───') + c('38;5;220', ' ' + message + ' ') + c('38;5;245', '───');
    case 'success':
      return '  ' + c('38;5;154', '[✓]') + c('0;37', ' ' + message);
    case 'error':
      return '  ' + c('38;5;196', '[✗]') + c('0;37', ' ' + message);
    case 'info':
    default:
      return '  ' + c('38;5;240', '[·]') + c('38;5;245', ' ' + message);
  }
}

// ─────────────────────────────────────────────
// Command executor
// ─────────────────────────────────────────────
async function executeCommand(command, term) {
  const parts = command.trim().split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1);

  try {
    switch (cmd) {

      case 'scan': {
        if (!args[0]) {
          term.writeln(c('38;5;196', '[✗]') + ' URL required — usage: ' + c('38;5;220', 'scan') + ' <url>');
          return;
        }
        const url = args[0];
        const depthIdx = args.indexOf('--depth');
        const timeoutIdx = args.indexOf('--timeout');
        const depth   = depthIdx   >= 0 ? parseInt(args[depthIdx + 1])   : undefined;
        const timeout = timeoutIdx >= 0 ? parseInt(args[timeoutIdx + 1]) : undefined;

        term.writeln('');
        term.writeln(c('38;5;220', '[»] Target:') + '  ' + c('0;37', url));
        if (depth)   term.writeln(c('38;5;220', '[»] Depth:')   + '   ' + c('0;37', String(depth)));
        if (timeout) term.writeln(c('38;5;220', '[»] Timeout:') + ' '  + c('0;37', timeout + 's'));
        term.writeln('');

        const payload = { url };
        if (depth)   payload.depth = depth;
        if (timeout) payload.timeout = timeout;

        const resp = await axios.post(`${API_URL}/api/scan`, payload);
        const scanId = resp.data.scan_id;

        term.writeln(c('38;5;154', '[✓]') + ' Scan started — ID: ' + c('38;5;220', scanId));
        term.writeln(c('38;5;240', '    run ') + c('38;5;245', 'status ' + scanId) + c('38;5;240', ' to check · ') + c('38;5;245', 'download ' + scanId) + c('38;5;240', ' for PDF'));
        term.writeln('');
        break;
      }

      case 'status': {
        if (!args[0]) {
          term.writeln(c('38;5;196', '[✗]') + ' Scan ID required — usage: ' + c('38;5;220', 'status') + ' <id>');
          return;
        }
        const resp = await axios.get(`${API_URL}/api/scan/${args[0]}`);
        const d = resp.data;
        const statusColor = d.status === 'completed' ? '154' : d.status === 'failed' ? '196' : '220';

        term.writeln('');
        term.writeln(c('38;5;220', ' Scan Status') + c('38;5;240', ' ──────────────────────────────────────'));
        term.writeln('  ' + c('38;5;245', 'ID        ') + c('0;37', d.scan_id));
        term.writeln('  ' + c('38;5;245', 'Target    ') + c('0;37', d.target));
        if (d.scan_type) term.writeln('  ' + c('38;5;245', 'Type      ') + c('0;37', d.scan_type));
        term.writeln('  ' + c('38;5;245', 'Status    ') + c('38;5;' + statusColor, d.status));
        term.writeln('  ' + c('38;5;245', 'Vulns     ') + c('38;5;196', String(d.total_vulnerabilities || 0)));
        if (d.deep_state_summary?.mutations || d.deep_state_summary?.wizard_steps) {
          term.writeln('  ' + c('38;5;245', 'DeepState ') + c('0;37', `${d.deep_state_summary.mutations || 0} mutations · ${d.deep_state_summary.wizard_steps || 0} wizard steps · ${d.deep_state_summary.revealed_hints || 0} hints`));
        }
        if (d.intelligent_mutation?.mutation_attempts) {
          term.writeln('  ' + c('38;5;245', 'Mutation  ') + c('0;37', `${d.intelligent_mutation.mutation_attempts} adaptive retries · ${d.intelligent_mutation.confirmed || 0} confirmed`));
        }
        if (d.oob_mapping_summary?.tracked_injections) {
          term.writeln('  ' + c('38;5;245', 'OOB Map   ') + c('0;37', `${d.oob_mapping_summary.tracked_injections} probes · ${d.oob_mapping_summary.callbacks || 0} callbacks`));
        }
        if (d.summary && Object.keys(d.summary).length > 0) {
          const parts = Object.entries(d.summary)
            .filter(([, value]) => value)
            .map(([key, value]) => `${key}:${value}`);
          if (parts.length) {
            term.writeln('  ' + c('38;5;245', 'Summary   ') + c('0;37', parts.join(' · ')));
          }
        }
        if (d.tech_stack?.primary_language) {
          const frameworks = Array.isArray(d.tech_stack.frameworks) && d.tech_stack.frameworks.length
            ? d.tech_stack.frameworks.join(', ')
            : 'none';
          term.writeln('  ' + c('38;5;245', 'Stack     ') + c('0;37', `${d.tech_stack.primary_language} · ${frameworks}`));
        }
        term.writeln('');
        if (d.status === 'completed') {
          term.writeln(c('38;5;240', '  run ') + c('38;5;245', 'download ' + d.scan_id) + c('38;5;240', ' for PDF report'));
        }
        break;
      }

      case 'download': {
        if (!args[0]) {
          term.writeln(c('38;5;196', '[✗]') + ' Scan ID required — usage: ' + c('38;5;220', 'download') + ' <id>');
          return;
        }
        window.open(`${API_URL}/api/download/${args[0]}`, '_blank');
        term.writeln(c('38;5;154', '[✓]') + ' PDF download initiated for ' + c('38;5;220', args[0]));
        break;
      }

      case 'help': {
        term.writeln('');
        term.writeln(c('38;5;220', ' Commands') + c('38;5;240', ' ──────────────────────────────────────────'));
        const cmds = [
          ['scan <url>',              'Start a vulnerability scan'],
          ['scan <url> --depth 3',    'Scan with custom crawl depth'],
          ['scan <url> --timeout 20', 'Scan with custom timeout (seconds)'],
          ['scanrepo <url>',              'SAST scan a GitHub repository'],
          ['scanrepo <url> --token xxx',  'Scan private repo with GitHub token'],
          ['scanrepo <url> --branch dev', 'Scan a specific branch'],
          ['status <id>',             'Check scan progress and results'],
          ['download <id>',           'Download PDF vulnerability report'],
          ['help',                    'Show this help'],
          ['clear',                   'Clear terminal'],
        ];
        cmds.forEach(([cmd2, desc]) => {
          term.writeln('  ' + c('38;5;220', cmd2.padEnd(28)) + c('38;5;245', ' ' + desc));
        });
        term.writeln('');
        term.writeln(c('38;5;240', ' Engines: adaptive XSS bypass · deep-state SPA mutation · cross-file taint · OOB network profiling'));
        term.writeln(c('38;5;240', ' OWASP Coverage: A01 A02 A03 A05 A06 A08 A10'));
        term.writeln('');
        break;
      }

      case 'clear':
      case 'cls': {
        term.clear();
        printBanner(term);
        break;
      }

      case 'scanrepo': {
        if (!args[0]) {
          term.writeln(c('38;5;196', '[✗]') + ' Repo URL required — usage: ' + c('38;5;220', 'scanrepo') + ' <github-url> [--token ghp_xxx] [--branch main]');
          return;
        }
        const repoUrl = args[0];
        const tokenIdx  = args.indexOf('--token');
        const branchIdx = args.indexOf('--branch');
        const token  = tokenIdx  >= 0 ? args[tokenIdx + 1]  : undefined;
        const branch = branchIdx >= 0 ? args[branchIdx + 1] : undefined;

        term.writeln('');
        term.writeln(c('38;5;220', '[»] Repo:')   + '    ' + c('0;37', repoUrl));
        term.writeln(c('38;5;220', '[»] Mode:')   + '    ' + c('0;37', 'SAST (Static Analysis)'));
        if (branch) term.writeln(c('38;5;220', '[»] Branch:') + '  ' + c('0;37', branch));
        if (token)  term.writeln(c('38;5;220', '[»] Token:')  + '   ' + c('0;37', token.slice(0, 8) + '...'));
        term.writeln('');
        term.writeln(c('38;5;245', '  Scanning for: secrets · dangerous functions · vulnerable deps · misconfigs'));
        term.writeln('');

        const payload = { url: repoUrl };
        if (token)  payload.token  = token;
        if (branch) payload.branch = branch;

        const resp = await axios.post(`${API_URL}/api/scan/repo`, payload);
        const scanId = resp.data.scan_id;

        term.writeln(c('38;5;154', '[✓]') + ' SAST scan started — ID: ' + c('38;5;220', scanId));
        term.writeln(c('38;5;240', '    run ') + c('38;5;245', 'status ' + scanId) + c('38;5;240', ' to check · ') + c('38;5;245', 'download ' + scanId) + c('38;5;240', ' for PDF'));
        term.writeln('');
        break;
      }

      default:
        term.writeln(c('38;5;196', '[✗]') + ' Unknown command: ' + c('0;37', cmd) + ' — type ' + c('38;5;220', 'help') + ' for commands');
    }
  } catch (err) {
    if (err?.code === 'ERR_NETWORK') {
      term.writeln(c('38;5;196', '[✗]') + ' API server not reachable at ' + c('38;5;220', API_URL));
      term.writeln(c('38;5;240', '    start backend: python api_server.py'));
      return;
    }

    term.writeln(c('38;5;196', '[✗]') + ' ' + err.message);
    if (err.response?.data?.error) {
      term.writeln(c('38;5;240', '    ' + err.response.data.error));
    }
  }
}

export default App;
