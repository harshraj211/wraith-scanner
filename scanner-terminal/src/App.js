import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import io from 'socket.io-client';
import axios from 'axios';
import 'xterm/css/xterm.css';
import './App.css';

const API_URL = 'http://localhost:5001';

function App() {
  const terminalRef = useRef(null);
  const [terminal, setTerminal] = useState(null);
  const [socket, setSocket] = useState(null);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [currentMode, setCurrentMode] = useState('scan');
  const [availableModes, setAvailableModes] = useState([]);

  // Fetch available modes on mount
  useEffect(() => {
    axios.get(`${API_URL}/api/modes`)
      .then(response => {
        setAvailableModes(response.data.modes);
      })
      .catch(err => console.error('Failed to fetch modes:', err));
  }, []);

  useEffect(() => {
    // Initialize terminal with professional theme
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: '"Fira Code", "Cascadia Code", Consolas, Monaco, "Courier New", monospace',
      theme: {
        background: '#0c0c0c',
        foreground: '#cccccc',
        cursor: '#00ff00',
        black: '#0c0c0c',
        red: '#c50f1f',
        green: '#13a10e',
        yellow: '#c19c00',
        blue: '#0037da',
        magenta: '#881798',
        cyan: '#3a96dd',
        white: '#cccccc',
        brightBlack: '#767676',
        brightRed: '#e74856',
        brightGreen: '#16c60c',
        brightYellow: '#f9f1a5',
        brightBlue: '#3b78ff',
        brightMagenta: '#b4009e',
        brightCyan: '#61d6d6',
        brightWhite: '#f2f2f2',
      },
      lineHeight: 1.2,
      letterSpacing: 0,
      scrollback: 1000,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);
    term.open(terminalRef.current);
    fitAddon.fit();

    // Professional banner
    term.writeln('');
    term.writeln('\x1b[1;32m┌─────────────────────────────────────────────────────────────┐\x1b[0m');
    term.writeln('\x1b[1;32m│                                                             │\x1b[0m');
    term.writeln('\x1b[1;32m│    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗   │\x1b[0m');
    term.writeln('\x1b[1;32m│    ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝   │\x1b[0m');
    term.writeln('\x1b[1;32m│    ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║        │\x1b[0m');
    term.writeln('\x1b[1;32m│    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║        │\x1b[0m');
    term.writeln('\x1b[1;32m│     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗   │\x1b[0m');
    term.writeln('\x1b[1;32m│      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   │\x1b[0m');
    term.writeln('\x1b[1;32m│                                                             │\x1b[0m');
    term.writeln('\x1b[1;32m│              \x1b[1;37mVulnerability Scanner v3.0\x1b[1;32m                  │\x1b[0m');
    term.writeln('\x1b[1;32m│              \x1b[0;37mMulti-Mode Security Testing\x1b[1;32m                │\x1b[0m');
    term.writeln('\x1b[1;32m│                                                             │\x1b[0m');
    term.writeln('\x1b[1;32m└─────────────────────────────────────────────────────────────┘\x1b[0m');
    term.writeln('');
    term.writeln('\x1b[1;33m[*] Available Commands:\x1b[0m');
    term.writeln('    \x1b[1;36mscan\x1b[0m <url>              Start vulnerability scan');
    term.writeln('    \x1b[1;36mmode\x1b[0m <mode>             Switch scanning mode');
    term.writeln('    \x1b[1;36mmodes\x1b[0m                   List available modes');
    term.writeln('    \x1b[1;36mdownload\x1b[0m <scan_id>      Download PDF report');
    term.writeln('    \x1b[1;36mstatus\x1b[0m <scan_id>        Check scan progress');
    term.writeln('    \x1b[1;36mhelp\x1b[0m                   Display available commands');
    term.writeln('    \x1b[1;36mclear\x1b[0m                  Clear terminal screen');
    term.writeln('');
    term.writeln(`\x1b[1;32m[✓] Current Mode:\x1b[0m ${currentMode.toUpperCase()}`);
    term.writeln('\x1b[0;90m[i] Type "modes" to see all available modes\x1b[0m');
    term.writeln('');
    term.write('\x1b[1;32m┌──(\x1b[1;34mscanner\x1b[1;32m)-[\x1b[1;37m~\x1b[1;32m]\x1b[0m\n\x1b[1;32m└─$\x1b[0m ');

    setTerminal(term);

    // Connect WebSocket
    const ws = io(API_URL);
    
    ws.on('connect', () => {
      console.log('WebSocket connected');
    });

    ws.on('scan_progress', (data) => {
      const { message, type } = data;
      let prefix = '';
      let color = '\x1b[0m';

      if (type === 'phase') {
        prefix = '[+]';
        color = '\x1b[1;35m';
      } else if (type === 'success') {
        prefix = '[✓]';
        color = '\x1b[1;32m';
      } else if (type === 'warning') {
        prefix = '[!]';
        color = '\x1b[1;33m';
      } else if (type === 'error') {
        prefix = '[✗]';
        color = '\x1b[1;31m';
      } else {
        prefix = '[*]';
        color = '\x1b[0;37m';
      }

      term.writeln(`${color}${prefix} ${message}\x1b[0m`);
    });

    ws.on('disconnect', () => {
      term.writeln('\x1b[1;31m[✗] WebSocket connection lost\x1b[0m');
    });

    setSocket(ws);

    // Handle window resize
    const handleResize = () => fitAddon.fit();
    window.addEventListener('resize', handleResize);

    return () => {
      term.dispose();
      ws.disconnect();
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const executeCommand = async (command) => {
    const parts = command.split(' ');
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1);

    try {
      if (cmd === 'scan') {
        if (args.length === 0) {
          terminal.writeln('\x1b[1;31m[✗] Error: URL parameter required\x1b[0m');
          terminal.writeln('\x1b[0;37m    Usage: scan <target_url>\x1b[0m');
          terminal.writeln('\x1b[0;37m    Example: scan http://example.com\x1b[0m');
          return;
        }

        const url = args[0];
        terminal.writeln(`\x1b[1;36m[*] Initiating scan: ${url}\x1b[0m`);
        terminal.writeln(`\x1b[1;36m[*] Mode: ${currentMode.toUpperCase()}\x1b[0m`);
        terminal.writeln('');
        
        const response = await axios.post(`${API_URL}/api/scan`, { 
          url,
          mode: currentMode 
        });
        const scanId = response.data.scan_id;
        
        setCurrentScanId(scanId);
        terminal.writeln(`\x1b[1;32m[✓] Scan ID: \x1b[1;37m${scanId}\x1b[0m`);
        terminal.writeln('\x1b[0;90m[i] Real-time updates will appear below...\x1b[0m');
        terminal.writeln('');
      }
      else if (cmd === 'mode') {
        if (args.length === 0) {
          terminal.writeln('\x1b[1;31m[✗] Error: Mode parameter required\x1b[0m');
          terminal.writeln('\x1b[0;37m    Usage: mode <mode_name>\x1b[0m');
          terminal.writeln('\x1b[0;37m    Available: scan, lab, ctf, ctf-auth\x1b[0m');
          return;
        }

        const newMode = args[0].toLowerCase();
        const validModes = ['scan', 'lab', 'ctf', 'ctf-auth'];
        
        if (!validModes.includes(newMode)) {
          terminal.writeln(`\x1b[1;31m[✗] Invalid mode: ${newMode}\x1b[0m`);
          terminal.writeln(`\x1b[0;37m    Valid modes: ${validModes.join(', ')}\x1b[0m`);
          return;
        }

        // Show warning for dangerous modes
        if (newMode === 'ctf' || newMode === 'ctf-auth') {
          terminal.writeln('');
          terminal.writeln('\x1b[1;31m' + '='.repeat(60) + '\x1b[0m');
          terminal.writeln('\x1b[1;31m⚠️  EXPLOITATION MODE\x1b[0m');
          terminal.writeln('\x1b[1;31m' + '='.repeat(60) + '\x1b[0m');
          terminal.writeln('\x1b[1;33mThis mode performs ACTIVE EXPLOITATION.\x1b[0m');
          terminal.writeln('\x1b[1;33mUse ONLY on CTFs, labs, and authorized targets.\x1b[0m');
          terminal.writeln('\x1b[1;31m' + '='.repeat(60) + '\x1b[0m');
          terminal.writeln('');
        }

        setCurrentMode(newMode);
        terminal.writeln(`\x1b[1;32m[✓] Mode changed to: ${newMode.toUpperCase()}\x1b[0m`);
        
        // Get mode description
        const modeInfo = availableModes.find(m => m.name === newMode);
        if (modeInfo) {
          terminal.writeln(`\x1b[0;37m    ${modeInfo.description}\x1b[0m`);
        }
      }
      else if (cmd === 'modes') {
        terminal.writeln('\x1b[1;33m[*] Available Scanning Modes:\x1b[0m');
        terminal.writeln('');
        
        availableModes.forEach(mode => {
          const indicator = mode.name === currentMode ? '\x1b[1;32m►\x1b[0m' : ' ';
          terminal.writeln(`${indicator} \x1b[1;36m${mode.name.padEnd(12)}\x1b[0m ${mode.description}`);
          mode.features.forEach(feature => {
            terminal.writeln(`    \x1b[0;90m• ${feature}\x1b[0m`);
          });
          terminal.writeln('');
        });
        
        terminal.writeln(`\x1b[1;32m[✓] Current mode: ${currentMode.toUpperCase()}\x1b[0m`);
        terminal.writeln('\x1b[0;37m    Use: mode <name> to switch\x1b[0m');
      }
      else if (cmd === 'download') {
        if (args.length === 0) {
          terminal.writeln('\x1b[1;31m[✗] Error: Scan ID required\x1b[0m');
          terminal.writeln('\x1b[0;37m    Usage: download <scan_id>\x1b[0m');
          return;
        }

        const scanId = args[0];
        terminal.writeln(`\x1b[1;36m[*] Downloading report: ${scanId}\x1b[0m`);
        
        window.open(`${API_URL}/api/download/${scanId}`, '_blank');
        terminal.writeln('\x1b[1;32m[✓] Report download initiated\x1b[0m');
      }
      else if (cmd === 'status') {
        if (args.length === 0) {
          terminal.writeln('\x1b[1;31m[✗] Error: Scan ID required\x1b[0m');
          terminal.writeln('\x1b[0;37m    Usage: status <scan_id>\x1b[0m');
          return;
        }

        const scanId = args[0];
        terminal.writeln(`\x1b[1;36m[*] Retrieving scan status...\x1b[0m`);
        
        const response = await axios.get(`${API_URL}/api/scan/${scanId}`);
        const data = response.data;
        
        terminal.writeln('');
        terminal.writeln(`\x1b[1;37m    Scan ID:            \x1b[0m${data.scan_id}`);
        terminal.writeln(`\x1b[1;37m    Target:             \x1b[0m${data.target}`);
        terminal.writeln(`\x1b[1;37m    Mode:               \x1b[0m${(data.mode || 'scan').toUpperCase()}`);
        terminal.writeln(`\x1b[1;37m    Status:             \x1b[0m${data.status}`);
        terminal.writeln(`\x1b[1;37m    Vulnerabilities:    \x1b[0m${data.total_vulnerabilities || 0}`);
        
        if (data.total_flags !== undefined) {
          terminal.writeln(`\x1b[1;37m    Flags Captured:     \x1b[1;33m${data.total_flags} 🏁\x1b[0m`);
        }
        
        terminal.writeln('');
      }
      else if (cmd === 'clear' || cmd === 'cls') {
        terminal.clear();
      }
      else if (cmd === 'help') {
        terminal.writeln('\x1b[1;33m[*] Available Commands:\x1b[0m');
        terminal.writeln('    \x1b[1;36mscan\x1b[0m <url>              Start vulnerability scan');
        terminal.writeln('    \x1b[1;36mmode\x1b[0m <mode>             Switch scanning mode');
        terminal.writeln('    \x1b[1;36mmodes\x1b[0m                   List available modes');
        terminal.writeln('    \x1b[1;36mdownload\x1b[0m <scan_id>      Download PDF report');
        terminal.writeln('    \x1b[1;36mstatus\x1b[0m <scan_id>        Check scan progress');
        terminal.writeln('    \x1b[1;36mhelp\x1b[0m                   Display available commands');
        terminal.writeln('    \x1b[1;36mclear\x1b[0m                  Clear terminal screen');
      }
      else {
        terminal.writeln(`\x1b[1;31m[✗] Unknown command: ${cmd}\x1b[0m`);
        terminal.writeln('\x1b[0;90m[i] Type "help" for available commands\x1b[0m');
      }
    } catch (error) {
      terminal.writeln(`\x1b[1;31m[✗] Error: ${error.message}\x1b[0m`);
      if (error.response) {
        terminal.writeln(`\x1b[0;90m    Status: ${error.response.status}\x1b[0m`);
      }
    }
  };

  useEffect(() => {
    if (!terminal) return;

    let currentLine = '';

    const handleData = async (data) => {
      const code = data.charCodeAt(0);

      if (code === 13) { // Enter
        terminal.writeln('');
        const command = currentLine.trim();
        
        if (command) {
          await executeCommand(command);
        }
        
        currentLine = '';
        terminal.write('\x1b[1;32m┌──(\x1b[1;34mscanner\x1b[1;32m)-[\x1b[1;37m~\x1b[1;32m]\x1b[0m\n\x1b[1;32m└─$\x1b[0m ');
      }
      else if (code === 127) { // Backspace
        if (currentLine.length > 0) {
          currentLine = currentLine.slice(0, -1);
          terminal.write('\b \b');
        }
      }
      else if (code >= 32) { // Printable
        currentLine += data;
        terminal.write(data);
      }
    };

    const disposable = terminal.onData(handleData);
    
    return () => {
      disposable.dispose();
    };
  }, [terminal]);

  return (
    <div className="App">
      <div ref={terminalRef} className="terminal-container" />
    </div>
  );
}

export default App;