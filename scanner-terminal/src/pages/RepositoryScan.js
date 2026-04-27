import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import TerminalPanel from '../components/ui/TerminalPanel';

export default function RepositoryScan({ repoForm, updateRepoForm, submitRepoScan, repoState, progressEvents }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Repository"
        title="Repository Scan"
        description="Run Semgrep, taint analysis, secrets, and dependency CVE checks against GitHub repositories."
        actions={<Button onClick={submitRepoScan} disabled={repoState === 'scanning'}>{repoState === 'scanning' ? 'Scanning' : 'Scan Repository'}</Button>}
      />
      <div className="setup-grid">
        <Card title="GitHub Target" eyebrow="SAST">
          <label className="field">
            <span>Repository URL</span>
            <input value={repoForm.url} onChange={(event) => updateRepoForm('url', event.target.value)} placeholder="https://github.com/org/repo" />
          </label>
          <div className="form-grid">
            <label className="field"><span>Branch</span><input value={repoForm.branch} onChange={(event) => updateRepoForm('branch', event.target.value)} /></label>
            <label className="field"><span>GitHub Token</span><input value={repoForm.token} onChange={(event) => updateRepoForm('token', event.target.value)} /></label>
          </div>
        </Card>
        <TerminalPanel events={progressEvents} />
      </div>
    </div>
  );
}
