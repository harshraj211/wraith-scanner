import React, { useMemo, useState } from 'react';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';

const severityOrder = [
  ['critical', 'Critical'],
  ['high', 'High'],
  ['medium', 'Medium'],
  ['low', 'Low'],
  ['info', 'Info'],
];

const capabilities = [
  {
    icon: 'public',
    title: 'Web & API scanning',
    body: 'Crawl authorized targets, discover routes, test inputs, and store request evidence for DAST findings.',
    page: 'automated-setup',
  },
  {
    icon: 'code_blocks',
    title: 'Repository code scanning',
    body: 'Run repository SAST with Semgrep, taint analysis, secrets checks, dependency review, and language breakdowns.',
    page: 'repository',
  },
  {
    icon: 'hub',
    title: 'CVE & template coverage',
    body: 'Use Nuclei and CVE enrichment to connect exposed services, templates, and known vulnerability intelligence.',
    page: 'nuclei',
  },
  {
    icon: 'biotech',
    title: 'Manual testing suite',
    body: 'Inspect traffic, replay requests, fuzz parameters, decode payloads, and compare responses from one workspace.',
    page: 'manual',
  },
  {
    icon: 'verified_user',
    title: 'Proof verification',
    body: 'Turn high-confidence findings into safe proof tasks with sanitized evidence and repeatable validation context.',
    page: 'proof',
  },
  {
    icon: 'assessment',
    title: 'Professional reporting',
    body: 'Export WRAITH-branded PDF and JSON reports with findings, evidence, severity, and remediation guidance.',
    page: 'reports',
  },
];

const faqRows = [
  {
    question: 'What can I scan?',
    answer: 'WRAITH supports authorized web apps, APIs, source repositories, Nuclei targets, captured traffic, and manually imported request evidence.',
  },
  {
    question: 'What is the difference between Scan Setup and Cockpit?',
    answer: 'Scan Setup is where you configure and launch a mission. Cockpit is the live command view for progress, findings, health checks, and scan artifacts.',
  },
  {
    question: 'Can I scan repositories?',
    answer: 'Yes. Repository Scan clones the authorized repo, detects the language stack, runs SAST analyzers, and generates the same report artifacts.',
  },
  {
    question: 'What happens after a scan completes?',
    answer: 'Findings are normalized, evidence is saved to the local corpus, report files are generated, and the results become available across Cockpit, Findings, Evidence, and Reports.',
  },
  {
    question: 'Are reports downloadable?',
    answer: 'Yes. Completed scans expose WRAITH-branded PDF and JSON downloads named with the scan id and target or repository slug.',
  },
  {
    question: 'Does it save evidence?',
    answer: 'Yes. Requests, responses, findings, proof artifacts, and scan states are stored locally in the WRAITH SQLite corpus.',
  },
  {
    question: 'Is it safe to use?',
    answer: 'WRAITH is built around authorized targets and safe defaults. Higher-intensity actions are separated into explicit workflows and policy acknowledgements.',
  },
];

const workflow = [
  ['Configure', 'Define target, scope, auth, and safety settings.'],
  ['Scan', 'Run DAST, SAST, Nuclei, or manual workflows.'],
  ['Triage', 'Prioritize findings by severity and evidence.'],
  ['Verify', 'Capture proof tasks and validation context.'],
  ['Report', 'Export professional PDF and JSON artifacts.'],
];

function numberOrFallback(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function formatNumber(value) {
  return numberOrFallback(value).toLocaleString();
}

function toneForStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['completed', 'ready', 'online', 'enabled'].includes(value)) return 'emerald';
  if (['running', 'loading'].includes(value)) return 'blue';
  if (['failed', 'offline', 'error', 'unavailable'].includes(value)) return 'red';
  if (['missing', 'optional'].includes(value)) return 'amber';
  return 'slate';
}

function SeverityBars({ severity }) {
  const total = severityOrder.reduce((sum, [key]) => sum + numberOrFallback(severity?.[key]), 0);
  return (
    <div className="overview-severity-bars">
      {severityOrder.map(([key, label]) => {
        const count = numberOrFallback(severity?.[key]);
        const width = total > 0 ? Math.max(4, Math.round((count / total) * 100)) : 0;
        return (
          <div className="overview-severity-row" key={key}>
            <span>{label}</span>
            <div className="overview-severity-track">
              <i className={`severity-fill severity-fill-${key}`} style={{ width: `${width}%` }} />
            </div>
            <strong>{count}</strong>
          </div>
        );
      })}
    </div>
  );
}

function OverviewStat({ icon, label, value, detail, tone = 'cyan', hero = false }) {
  return (
    <div className={`overview-stat overview-stat-${tone} ${hero ? 'overview-stat-hero' : ''}`.trim()}>
      <span className="material-symbols-outlined">{icon}</span>
      <div>
        <em>{label}</em>
        <strong>{value}</strong>
        {detail && <small>{detail}</small>}
      </div>
    </div>
  );
}

export default function Overview({ onNavigate, stats, overview, overviewState }) {
  const [openFaq, setOpenFaq] = useState(0);
  const service = overview?.service || {};
  const storage = overview?.storage || {};
  const activeScans = overview?.active_scans || {};
  const totals = overview?.totals || {};
  const risk = overview?.risk || {};
  const severity = risk.severity || {};
  const serviceStatus = service.status || (overviewState === 'ready' ? 'online' : overviewState || 'standby');
  const storageStatus = storage.status || (overviewState === 'ready' ? 'ready' : overviewState || 'local');
  const totalScans = numberOrFallback(totals.scans, activeScans.total || storage.scan_count || 0);
  const completedScans = numberOrFallback(totals.completed_scans, activeScans.completed || 0);
  const runningScans = numberOrFallback(totals.running_scans, activeScans.running || 0);
  const findingsFound = numberOrFallback(totals.findings, risk.total_findings || stats?.findings || 0);
  const reportsGenerated = numberOrFallback(totals.reports, 0);
  const evidenceRequests = numberOrFallback(totals.evidence_requests, storage.request_count || stats?.requests || 0);
  const repositoriesScanned = numberOrFallback(totals.repositories_scanned, 0);
  const webScans = numberOrFallback(totals.web_scans, 0);
  const highSignal = numberOrFallback(severity.critical) + numberOrFallback(severity.high);

  const readiness = useMemo(() => ([
    ['Backend API', serviceStatus, serviceStatus === 'online' ? 'Local API is responding.' : 'API status is not online.'],
    ['Corpus Storage', storageStatus, storageStatus === 'ready' ? 'SQLite corpus is writable.' : 'Storage is not reporting ready.'],
    ['Reports', reportsGenerated ? 'enabled' : 'ready', reportsGenerated ? `${formatNumber(reportsGenerated)} report bundles generated.` : 'Reports generate after completed scans.'],
  ]), [reportsGenerated, serviceStatus, storageStatus]);

  return (
    <div className="page-stack overview-page overview-product-page">
      <section className="overview-product-hero">
        <div className="overview-intro-panel">
          <span className="eyebrow">WRAITH Overview</span>
          <h1>End-to-end vulnerability scanning from target setup to proof-ready reports.</h1>
          <p>
            WRAITH helps you scan authorized websites, APIs, repositories, CVEs, and manual traffic,
            then turns the results into evidence-backed findings and professional reports.
          </p>
          <div className="overview-action-row">
            <Button size="lg" onClick={() => onNavigate('automated-setup')}>
              <span className="material-symbols-outlined">play_arrow</span>
              Start Scan
            </Button>
            <Button size="lg" variant="secondary" onClick={() => onNavigate('repository')}>
              <span className="material-symbols-outlined">code_blocks</span>
              Scan Repository
            </Button>
            <Button size="lg" variant="ghost" onClick={() => onNavigate('reports')}>
              <span className="material-symbols-outlined">assessment</span>
              See Reports
            </Button>
          </div>
        </div>

        <aside className="overview-total-panel">
          <div className="overview-total-header">
            <span className="eyebrow">All-time usage</span>
            <Badge tone={toneForStatus(serviceStatus)}>{serviceStatus}</Badge>
          </div>
          <OverviewStat
            hero
            icon="radar"
            label="Total scans till now"
            value={formatNumber(totalScans)}
            detail={`${formatNumber(completedScans)} completed / ${formatNumber(runningScans)} running`}
          />
          <div className="overview-mini-stats">
            <OverviewStat icon="gavel" label="Findings found" value={formatNumber(findingsFound)} detail={`${formatNumber(highSignal)} critical/high`} tone={highSignal ? 'red' : 'emerald'} />
            <OverviewStat icon="description" label="Reports generated" value={formatNumber(reportsGenerated)} detail={`${formatNumber(totals.artifacts || 0)} artifacts`} tone="blue" />
            <OverviewStat icon="storage" label="Evidence requests" value={formatNumber(evidenceRequests)} detail="local corpus rows" tone="cyan" />
          </div>
        </aside>
      </section>

      <section className="overview-global-grid" aria-label="Global WRAITH totals">
        <OverviewStat icon="done_all" label="Completed scans" value={formatNumber(completedScans)} detail="all completed missions" tone="emerald" />
        <OverviewStat icon="public" label="Web scans" value={formatNumber(webScans)} detail="DAST scan states" tone="cyan" />
        <OverviewStat icon="source" label="Repositories scanned" value={formatNumber(repositoriesScanned)} detail="SAST scan states" tone="blue" />
        <OverviewStat icon="warning" label="Critical + high" value={formatNumber(highSignal)} detail="priority risk" tone={highSignal ? 'red' : 'slate'} />
      </section>

      <div className="overview-main-grid">
        <section className="overview-panel overview-capabilities-panel">
          <div className="overview-panel-header">
            <span className="eyebrow">What WRAITH does overall</span>
            <h2>Coverage from discovery to reporting</h2>
          </div>
          <div className="overview-capability-list">
            {capabilities.map((item) => (
              <button className="overview-capability-row" type="button" key={item.title} onClick={() => onNavigate(item.page)}>
                <span className="material-symbols-outlined">{item.icon}</span>
                <span>
                  <strong>{item.title}</strong>
                  <em>{item.body}</em>
                </span>
                <i className="material-symbols-outlined">chevron_right</i>
              </button>
            ))}
          </div>
        </section>

        <section className="overview-panel overview-faq-panel">
          <div className="overview-panel-header">
            <span className="eyebrow">Basic Q&A</span>
            <h2>Common questions before scanning</h2>
          </div>
          <div className="overview-faq-list">
            {faqRows.map((item, index) => {
              const open = openFaq === index;
              return (
                <button
                  className={open ? 'overview-faq-row open' : 'overview-faq-row'}
                  type="button"
                  key={item.question}
                  onClick={() => setOpenFaq(open ? -1 : index)}
                >
                  <span>
                    <strong>{index + 1}. {item.question}</strong>
                    {open && <em>{item.answer}</em>}
                  </span>
                  <i className="material-symbols-outlined">{open ? 'expand_less' : 'expand_more'}</i>
                </button>
              );
            })}
          </div>
        </section>
      </div>

      <div className="overview-lower-grid">
        <section className="overview-panel overview-workflow-panel">
          <div className="overview-panel-header">
            <span className="eyebrow">Typical workflow</span>
            <h2>From setup to export</h2>
          </div>
          <div className="overview-workflow-strip">
            {workflow.map(([title, body], index) => (
              <div className="overview-workflow-step" key={title}>
                <span>{index + 1}</span>
                <strong>{title}</strong>
                <em>{body}</em>
              </div>
            ))}
          </div>
        </section>

        <section className="overview-panel overview-readiness-panel">
          <div className="overview-panel-header">
            <span className="eyebrow">Runtime readiness</span>
            <h2>Connected systems</h2>
          </div>
          <div className="overview-readiness-list">
            {readiness.map(([label, status, body]) => (
              <div key={label}>
                <span>
                  <strong>{label}</strong>
                  <em>{body}</em>
                </span>
                <Badge tone={toneForStatus(status)}>{status}</Badge>
              </div>
            ))}
          </div>
          <SeverityBars severity={severity} />
        </section>
      </div>
    </div>
  );
}
