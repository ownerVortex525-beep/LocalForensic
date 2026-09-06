'use client';

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Search,
  FolderArchive,
  Cpu,
  FileText,
  FileCheck,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Download,
  Trash2,
  Eye,
  Terminal,
  Activity,
  Server,
  Layers,
  FileCode,
  Crosshair,
  Sparkles,
  ChevronRight,
  ExternalLink,
  Hash,
  Database
} from 'lucide-react';

interface Stats {
  active_containers: number;
  total_containers: number;
  total_files_scanned: number;
  total_entities: number;
  total_records: number;
  last_scan_time: string | null;
  db_size_bytes: number;
}

interface ContainerItem {
  id: string;
  name: string;
  path: string;
  type: string;
  enabled: boolean;
  file_count: number;
  last_scanned: string | null;
}

interface PrimaryMatch {
  entity_id: number;
  field_type: string;
  raw_value: string;
  normalized_value: string;
  source_file: string;
  container_id: string;
  container_name: string;
  line_number: number;
  confidence: string;
  context_snippet: string;
}

interface RecordCluster {
  record_id: string;
  primary_match: PrimaryMatch;
  connected_fields: Record<string, string>;
  all_entities?: any[];
}

export default function ForensicWorkbenchPage() {
  const [activeTab, setActiveTab] = useState<'search' | 'containers' | 'scanner' | 'audit'>('search');
  const [stats, setStats] = useState<Stats | null>(null);
  const [fieldTypes, setFieldTypes] = useState<string[]>([]);
  const [containers, setContainers] = useState<ContainerItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchMode, setSearchMode] = useState('global');
  const [customField, setCustomField] = useState('email');
  const [exactMatch, setExactMatch] = useState(false);
  const [searchResults, setSearchResults] = useState<{
    result_count: number;
    scan_sources: number;
    execution_time_ms: number;
    results: RecordCluster[];
  } | null>(null);
  const [selectedCluster, setSelectedCluster] = useState<RecordCluster | null>(null);

  // Containers Form
  const [newContainerName, setNewContainerName] = useState('');
  const [newContainerPath, setNewContainerPath] = useState('');
  const [newContainerType, setNewContainerType] = useState('folder');

  // Scanner state
  const [scannerProgress, setScannerProgress] = useState<{
    status: string;
    progress_pct: number;
    current_file: string;
    files_scanned: number;
    total_files: number;
    entities_found: number;
  }>({
    status: 'idle',
    progress_pct: 0,
    current_file: '',
    files_scanned: 0,
    total_files: 0,
    entities_found: 0,
  });

  // Audit logs
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  const refreshStatus = async () => {
    try {
      const res = await fetch('/api/workbench?action=status');
      const data = await res.json();
      if (data.stats) {
        setStats(data.stats);
      }
      if (data.field_types) {
        setFieldTypes(data.field_types);
      }
      if (data.scan_status) {
        setScannerProgress(data.scan_status);
      }
    } catch (e) {
      console.error('Failed to load status', e);
    }
  };

  const loadContainers = async () => {
    try {
      const res = await fetch('/api/workbench?action=containers');
      const data = await res.json();
      if (Array.isArray(data)) {
        setContainers(data);
      }
    } catch (e) {
      console.error('Failed to load containers', e);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const res = await fetch('/api/workbench?action=logs&limit=50');
      const data = await res.json();
      if (Array.isArray(data)) {
        setAuditLogs(data);
      }
    } catch (e) {
      console.error('Failed to load audit logs', e);
    }
  };

  useEffect(() => {
    let ignore = false;
    async function init() {
      try {
        const [statusRes, contRes] = await Promise.all([
          fetch('/api/workbench?action=status'),
          fetch('/api/workbench?action=containers'),
        ]);
        const statusData = await statusRes.json();
        const contData = await contRes.json();
        if (!ignore) {
          if (statusData.stats) setStats(statusData.stats);
          if (statusData.field_types) setFieldTypes(statusData.field_types);
          if (statusData.scan_status) setScannerProgress(statusData.scan_status);
          if (Array.isArray(contData)) setContainers(contData);
        }
      } catch (e) {
        console.error('Initial load error', e);
      }
    }
    init();
    return () => {
      ignore = true;
    };
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!searchQuery.trim()) return;

    setLoading(true);
    setStatusMessage('Searching indexed forensic records...');
    try {
      const res = await fetch('/api/workbench', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'search',
          query: searchQuery.trim(),
          mode: searchMode,
          field: searchMode === 'custom' ? customField : undefined,
          exact: exactMatch
        })
      });
      const data = await res.json();
      setSearchResults(data);
      setStatusMessage(null);
    } catch (err: any) {
      setStatusMessage(`Search failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAddContainer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newContainerPath) return;

    setLoading(true);
    try {
      await fetch('/api/workbench', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'container_add',
          name: newContainerName || newContainerPath,
          path: newContainerPath,
          type: newContainerType
        })
      });
      setNewContainerName('');
      setNewContainerPath('');
      await loadContainers();
      await refreshStatus();
    } catch (err) {
      console.error('Error adding container', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleContainer = async (id: string, enabled: boolean) => {
    try {
      await fetch('/api/workbench', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'container_toggle',
          id,
          enabled
        })
      });
      await loadContainers();
    } catch (err) {
      console.error('Toggle error', err);
    }
  };

  const handleRemoveContainer = async (id: string) => {
    if (!confirm(`Are you sure you want to remove container ${id}?`)) return;
    try {
      await fetch('/api/workbench', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'container_remove',
          id
        })
      });
      await loadContainers();
      await refreshStatus();
    } catch (err) {
      console.error('Remove error', err);
    }
  };

  const handleTriggerScan = async (force = false, containerId?: string) => {
    setLoading(true);
    setStatusMessage(force ? 'Executing deep rescan on all containers...' : 'Executing incremental scan...');
    try {
      const res = await fetch('/api/workbench', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'scan_start',
          force,
          container_id: containerId
        })
      });
      const data = await res.json();
      if (data.status) {
        setScannerProgress(data.status);
      }
      await refreshStatus();
      await loadContainers();
      setStatusMessage('Scan completed successfully.');
    } catch (err: any) {
      setStatusMessage(`Scan failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateSamples = async () => {
    setLoading(true);
    setStatusMessage('Generating synthetic forensic evidence samples & indexing...');
    try {
      await fetch('/api/workbench', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'init_samples' })
      });
      await refreshStatus();
      await loadContainers();
      setStatusMessage('Synthetic incident samples initialized and indexed.');
    } catch (err: any) {
      setStatusMessage(`Initialization failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleExportFullReport = async () => {
    try {
      const res = await fetch('/api/workbench?action=export');
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_audit_report_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert('Failed to export report');
    }
  };

  return (
    <div className="min-h-screen bg-[#080808] text-[#E5E5E5] flex flex-col font-sans selection:bg-[#D4AF37] selection:text-black">
      {/* Top Header Bar */}
      <header className="border-b border-white/10 bg-[#080808] px-8 py-4 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-40">
        <div className="flex items-center gap-4">
          <div className="w-9 h-9 border border-white/20 bg-white/5 flex items-center justify-center text-[#D4AF37]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="font-light text-sm md:text-base tracking-[0.25em] text-white uppercase">
                Forensic Data Correlation Workbench
              </h1>
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 bg-[#D4AF37]/10 text-[#D4AF37] border border-[#D4AF37]/30 tracking-[0.2em] uppercase">
                LOCAL-ONLY
              </span>
            </div>
            <p className="text-xs text-white/40 tracking-wider font-light mt-0.5">Air-Gapped Forensic Discovery, Entity Clustering & Privacy Audit</p>
          </div>
        </div>

        {/* Security & Operational Indicators */}
        <div className="flex items-center gap-5 text-xs font-mono">
          <div className="flex items-center gap-2.5 px-3 py-1.5 bg-white/5 border border-white/10 text-white text-[11px] tracking-[0.15em] uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-[#D4AF37] animate-pulse"></span>
            AIR-GAPPED OPERATIONAL
          </div>
          {stats && (
            <div className="hidden md:flex items-center gap-3 text-white/40 font-mono text-xs">
              <span>DB: <strong className="text-white">{(stats.db_size_bytes / 1024).toFixed(0)} KB</strong></span>
              <span className="text-white/20">•</span>
              <span>Clusters: <strong className="text-[#D4AF37]">{stats.total_records}</strong></span>
              <span className="text-white/20">•</span>
              <span>Entities: <strong className="text-white">{stats.total_entities}</strong></span>
            </div>
          )}
        </div>
      </header>

      {/* Metric Strip */}
      <div className="border-b border-white/10 bg-[#0C0C0C] px-8 py-4">
        <div className="max-w-7xl mx-auto grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-4 bg-white/[0.02] border border-white/10 hover:border-white/20 transition-colors">
            <div className="text-white/40 text-[9px] uppercase tracking-[0.25em] font-medium mb-1">Active Containers</div>
            <div className="text-2xl font-serif text-white">{stats?.active_containers ?? 0} <span className="text-sm font-sans text-white/40 font-normal">/ {stats?.total_containers ?? 0}</span></div>
          </div>
          <div className="p-4 bg-white/[0.02] border border-white/10 hover:border-white/20 transition-colors">
            <div className="text-white/40 text-[9px] uppercase tracking-[0.25em] font-medium mb-1">Files Indexed</div>
            <div className="text-2xl font-serif text-white">{stats?.total_files_scanned ?? 0}</div>
          </div>
          <div className="p-4 bg-white/[0.02] border border-white/10 hover:border-white/20 transition-colors">
            <div className="text-white/40 text-[9px] uppercase tracking-[0.25em] font-medium mb-1">Entities Extracted</div>
            <div className="text-2xl font-serif text-[#D4AF37]">{stats?.total_entities ?? 0}</div>
          </div>
          <div className="p-4 bg-white/[0.02] border border-white/10 hover:border-white/20 transition-colors">
            <div className="text-white/40 text-[9px] uppercase tracking-[0.25em] font-medium mb-1">Record Clusters</div>
            <div className="text-2xl font-serif text-white">{stats?.total_records ?? 0}</div>
          </div>
        </div>
      </div>

      {/* Main Navigation Tabs */}
      <div className="border-b border-white/10 bg-[#080808] px-8">
        <div className="max-w-7xl mx-auto flex gap-2">
          <button
            id="tab-search"
            onClick={() => setActiveTab('search')}
            className={`flex items-center gap-2 px-5 py-3.5 text-[11px] uppercase tracking-[0.2em] font-medium border-b-2 transition-colors cursor-pointer ${
              activeTab === 'search'
                ? 'border-[#D4AF37] text-white bg-white/[0.03]'
                : 'border-transparent text-white/40 hover:text-white hover:bg-white/[0.01]'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            Forensic Search & Correlation
          </button>
          <button
            id="tab-containers"
            onClick={() => setActiveTab('containers')}
            className={`flex items-center gap-2 px-5 py-3.5 text-[11px] uppercase tracking-[0.2em] font-medium border-b-2 transition-colors cursor-pointer ${
              activeTab === 'containers'
                ? 'border-[#D4AF37] text-white bg-white/[0.03]'
                : 'border-transparent text-white/40 hover:text-white hover:bg-white/[0.01]'
            }`}
          >
            <FolderArchive className="w-3.5 h-3.5" />
            Storage Containers ({containers.length})
          </button>
          <button
            id="tab-scanner"
            onClick={() => setActiveTab('scanner')}
            className={`flex items-center gap-2 px-5 py-3.5 text-[11px] uppercase tracking-[0.2em] font-medium border-b-2 transition-colors cursor-pointer ${
              activeTab === 'scanner'
                ? 'border-[#D4AF37] text-white bg-white/[0.03]'
                : 'border-transparent text-white/40 hover:text-white hover:bg-white/[0.01]'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            Forensic Scanner
          </button>
          <button
            id="tab-audit"
            onClick={() => {
              setActiveTab('audit');
              loadAuditLogs();
            }}
            className={`flex items-center gap-2 px-5 py-3.5 text-[11px] uppercase tracking-[0.2em] font-medium border-b-2 transition-colors cursor-pointer ${
              activeTab === 'audit'
                ? 'border-[#D4AF37] text-white bg-white/[0.03]'
                : 'border-transparent text-white/40 hover:text-white hover:bg-white/[0.01]'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Audit Logs & Export
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-8 space-y-8">
        {statusMessage && (
          <div className="p-4 bg-white/5 border border-white/15 text-xs font-mono text-white/80 flex items-center justify-between">
            <span className="flex items-center gap-2.5">
              <Activity className="w-4 h-4 animate-spin text-[#D4AF37]" />
              {statusMessage}
            </span>
            <button onClick={() => setStatusMessage(null)} className="text-white/40 hover:text-white cursor-pointer">✕</button>
          </div>
        )}

        {/* TAB 1: FORENSIC SEARCH & CORRELATION */}
        {activeTab === 'search' && (
          <div className="space-y-6">
            <div className="p-6 bg-[#0C0C0C] border border-white/10">
              <form onSubmit={handleSearch} className="space-y-4">
                <div className="flex flex-col md:flex-row gap-3">
                  <div className="relative flex-1">
                    <Search className="w-4 h-4 text-white/40 absolute left-3.5 top-3.5" />
                    <input
                      id="search-input-main"
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Enter target artifact: email, phone, name, IP, passport, username, VIN, etc..."
                      className="w-full bg-[#080808] border border-white/15 rounded-none px-10 py-3 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-[#D4AF37] font-mono"
                    />
                  </div>
                  <select
                    id="search-mode-select"
                    value={searchMode}
                    onChange={(e) => setSearchMode(e.target.value)}
                    className="bg-[#080808] border border-white/15 rounded-none px-4 py-3 text-xs text-white focus:outline-none focus:border-[#D4AF37] uppercase tracking-wider"
                  >
                    <option value="global">Mode: Global Search (All Fields)</option>
                    <option value="email">Mode: Email Address</option>
                    <option value="phone">Mode: Phone & WhatsApp</option>
                    <option value="number">Mode: Number (Phone, ID, Tax, SSN, Car)</option>
                    <option value="name">Mode: Full Name & Contact</option>
                    <option value="address">Mode: Address & Location</option>
                    <option value="passport">Mode: Passport & Document</option>
                    <option value="username">Mode: Username & Account</option>
                    <option value="ip">Mode: IP Address</option>
                    <option value="domain">Mode: Domain & URL</option>
                    <option value="social">Mode: Social (VK, Telegram, Steam)</option>
                    <option value="auth">Mode: Auth / Hash Artifacts</option>
                    <option value="vehicle">Mode: Vehicle & VIN</option>
                    <option value="company">Mode: Company Name</option>
                    <option value="custom">Mode: Targeted Field...</option>
                  </select>

                  {searchMode === 'custom' && (
                    <select
                      value={customField}
                      onChange={(e) => setCustomField(e.target.value)}
                      className="bg-[#080808] border border-white/15 rounded-none px-4 py-3 text-xs text-[#D4AF37] focus:outline-none focus:border-[#D4AF37] font-mono"
                    >
                      {fieldTypes.map((ft) => (
                        <option key={ft} value={ft}>{ft}</option>
                      ))}
                    </select>
                  )}

                  <button
                    id="btn-execute-search"
                    type="submit"
                    disabled={loading}
                    className="px-7 py-3 bg-white text-black font-bold text-[11px] uppercase tracking-[0.2em] hover:bg-[#D4AF37] transition-colors rounded-none flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {loading ? <Activity className="w-4 h-4 animate-spin" /> : <Crosshair className="w-4 h-4" />}
                    Correlate
                  </button>
                </div>

                <div className="flex items-center justify-between text-xs text-white/40">
                  <div className="flex items-center gap-4">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={exactMatch}
                        onChange={(e) => setExactMatch(e.target.checked)}
                        className="rounded-none border-white/20 bg-[#080808] text-[#D4AF37] focus:ring-0"
                      />
                      <span className="text-white/60">Strict Exact Match Only</span>
                    </label>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="text-white/30 uppercase tracking-widest text-[9px]">Quick Reference:</span>
                    <button
                      type="button"
                      onClick={() => { setSearchQuery('Ivanov'); handleSearch(); }}
                      className="hover:text-[#D4AF37] underline transition-colors"
                    >
                      Ivanov
                    </button>
                    <span className="text-white/20">•</span>
                    <button
                      type="button"
                      onClick={() => { setSearchQuery('185.22.14.92'); handleSearch(); }}
                      className="hover:text-[#D4AF37] underline transition-colors"
                    >
                      185.22.14.92
                    </button>
                    <span className="text-white/20">•</span>
                    <button
                      type="button"
                      onClick={() => { setSearchQuery('+79161234567'); handleSearch(); }}
                      className="hover:text-[#D4AF37] underline transition-colors"
                    >
                      +79161234567
                    </button>
                  </div>
                </div>
              </form>
            </div>

            {/* Results Section */}
            {searchResults && (
              <div className="space-y-4">
                <div className="flex items-center justify-between text-xs text-white/50 font-mono tracking-wider">
                  <div>
                    FOUND <strong className="text-[#D4AF37]">{searchResults.result_count}</strong> RECORD CLUSTER(S) ACROSS{' '}
                    <strong className="text-white">{searchResults.scan_sources}</strong> EVIDENCE FILES IN{' '}
                    <strong className="text-white">{searchResults.execution_time_ms}MS</strong>
                  </div>
                </div>

                {searchResults.results.length === 0 ? (
                  <div className="p-12 text-center bg-[#0C0C0C] border border-white/10 text-white/40 text-xs tracking-wider uppercase font-mono">
                    No matching records found in indexed containers. Try broadening your query or running a full scan.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-4">
                    {searchResults.results.map((rec) => {
                      const p = rec.primary_match;
                      return (
                        <div
                          key={rec.record_id}
                          className="p-6 bg-[#0C0C0C] border border-white/10 hover:border-white/20 transition space-y-5"
                        >
                          {/* Match Header */}
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-4">
                            <div className="flex items-center gap-3">
                              <span className="px-2.5 py-0.5 text-[10px] font-mono font-semibold bg-[#D4AF37]/10 text-[#D4AF37] border border-[#D4AF37]/30 uppercase tracking-widest">
                                {p.field_type}
                              </span>
                              <span className="font-mono text-base font-bold text-white">
                                {p.raw_value}
                              </span>
                              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-white/5 text-white/70 border border-white/10">
                                Confidence: {p.confidence}
                              </span>
                            </div>
                            <button
                              onClick={() => setSelectedCluster(rec)}
                              className="text-xs font-mono uppercase tracking-[0.15em] text-white hover:text-[#D4AF37] flex items-center gap-1.5 cursor-pointer bg-white/5 px-3 py-1.5 border border-white/15 hover:border-white/40 transition-colors"
                            >
                              Cluster Inspector <ChevronRight className="w-3.5 h-3.5" />
                            </button>
                          </div>

                          {/* 2-Column Correlation Grid */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
                            {/* Connected Fields */}
                            <div className="space-y-2">
                              <div className="text-[10px] font-mono text-white/40 uppercase tracking-[0.2em]">
                                Correlated Secondary Entities in Cluster
                              </div>
                              <div className="space-y-2 bg-[#080808] p-4 border border-white/10">
                                {Object.entries(rec.connected_fields).map(([field, val]) => (
                                  <div key={field} className="flex items-start gap-2 font-mono">
                                    <span className="text-white/40 min-w-[130px] shrink-0 text-[11px] truncate uppercase tracking-wider">
                                      {field}:
                                    </span>
                                    <span className="text-white font-medium break-all">
                                      {val}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {/* Forensic Provenance */}
                            <div className="space-y-2">
                              <div className="text-[10px] font-mono text-white/40 uppercase tracking-[0.2em]">
                                Forensic Evidence Provenance
                              </div>
                              <div className="space-y-2.5 bg-[#080808] p-4 border border-white/10 font-mono text-[11px]">
                                <div className="text-white/50">
                                  Container: <strong className="text-white">{p.container_name}</strong>
                                </div>
                                <div className="text-white/50 truncate">
                                  File: <strong className="text-[#D4AF37]">{p.source_file}</strong> (Line {p.line_number})
                                </div>
                                <div className="text-white/30 text-[10px] uppercase tracking-wider pt-1">Surrounding Context:</div>
                                <pre className="bg-black p-3 border border-white/10 text-[11px] text-white/80 overflow-x-auto whitespace-pre-wrap break-all font-mono">
                                  {p.context_snippet}
                                </pre>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: STORAGE CONTAINERS */}
        {activeTab === 'containers' && (
          <div className="space-y-6">
            {/* Add Container Card */}
            <div className="p-6 bg-[#0C0C0C] border border-white/10 space-y-4">
              <h2 className="text-xs font-bold text-[#D4AF37] uppercase tracking-[0.3em] flex items-center gap-2">
                <FolderArchive className="w-4 h-4" />
                Register Evidence Container (500+ Multi-Source Support)
              </h2>
              <form onSubmit={handleAddContainer} className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <input
                  type="text"
                  value={newContainerName}
                  onChange={(e) => setNewContainerName(e.target.value)}
                  placeholder="Container Label (e.g. Incident Evidence 01)"
                  className="bg-[#080808] border border-white/15 rounded-none px-3 py-2.5 text-xs text-white placeholder:text-white/30 focus:outline-none focus:border-[#D4AF37]"
                />
                <input
                  type="text"
                  value={newContainerPath}
                  onChange={(e) => setNewContainerPath(e.target.value)}
                  placeholder="Directory or File Path (e.g. data/sample or /var/log)"
                  required
                  className="bg-[#080808] border border-white/15 rounded-none px-3 py-2.5 text-xs text-white placeholder:text-white/30 focus:outline-none focus:border-[#D4AF37] font-mono"
                />
                <select
                  value={newContainerType}
                  onChange={(e) => setNewContainerType(e.target.value)}
                  className="bg-[#080808] border border-white/15 rounded-none px-3 py-2.5 text-xs text-white focus:outline-none focus:border-[#D4AF37] uppercase tracking-wider"
                >
                  <option value="folder">Directory / Folder</option>
                  <option value="file">Single Evidence File</option>
                </select>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-2.5 bg-white text-black font-bold text-[11px] uppercase tracking-[0.2em] hover:bg-[#D4AF37] transition-colors rounded-none cursor-pointer disabled:opacity-50"
                >
                  + Add Container
                </button>
              </form>
            </div>

            {/* Containers List */}
            <div className="p-6 bg-[#0C0C0C] border border-white/10 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase text-white/40 tracking-[0.2em]">
                  Configured Evidence Sources ({containers.length})
                </h3>
                <button
                  onClick={loadContainers}
                  className="text-xs font-mono uppercase tracking-wider text-white/40 hover:text-white flex items-center gap-1.5 cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" /> Refresh
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="text-[10px] text-white/40 uppercase tracking-[0.2em] bg-white/[0.02] border-b border-white/10">
                    <tr>
                      <th className="px-4 py-3 font-mono">ID</th>
                      <th className="px-4 py-3">Name</th>
                      <th className="px-4 py-3 font-mono">Path</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Files</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 font-mono text-xs">
                    {containers.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-white/40 uppercase tracking-wider">
                          No containers configured yet. Register a folder or sample above.
                        </td>
                      </tr>
                    ) : (
                      containers.map((c) => (
                        <tr key={c.id} className="hover:bg-white/[0.02] transition-colors">
                          <td className="px-4 py-3 text-white/40 text-[10px]">{c.id}</td>
                          <td className="px-4 py-3 font-medium text-white font-sans">{c.name}</td>
                          <td className="px-4 py-3 text-white/60 truncate max-w-[200px]">{c.path}</td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 border border-white/15 bg-white/5 text-white/70 text-[10px] uppercase tracking-wider">
                              {c.type}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-white">{c.file_count}</td>
                          <td className="px-4 py-3">
                            <span
                              className={`px-2.5 py-0.5 text-[10px] tracking-wider uppercase font-semibold ${
                                c.enabled
                                  ? 'bg-[#D4AF37]/10 text-[#D4AF37] border border-[#D4AF37]/30'
                                  : 'bg-white/5 text-white/40 border border-white/10'
                              }`}
                            >
                              {c.enabled ? 'ENABLED' : 'DISABLED'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-right space-x-2">
                            <button
                              onClick={() => handleTriggerScan(false, c.id)}
                              className="px-2.5 py-1 bg-white/5 text-white border border-white/15 hover:border-white text-[10px] uppercase tracking-wider transition-colors cursor-pointer"
                            >
                              Scan
                            </button>
                            <button
                              onClick={() => handleToggleContainer(c.id, !c.enabled)}
                              className="px-2.5 py-1 bg-transparent text-white/70 hover:text-white border border-white/15 text-[10px] uppercase tracking-wider transition-colors cursor-pointer"
                            >
                              {c.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button
                              onClick={() => handleRemoveContainer(c.id)}
                              className="px-2.5 py-1 bg-transparent text-rose-300 hover:text-rose-200 border border-rose-500/30 hover:border-rose-400 text-[10px] uppercase tracking-wider transition-colors cursor-pointer"
                            >
                              Remove
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: FORENSIC SCANNER */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            <div className="p-6 bg-[#0C0C0C] border border-white/10 space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h2 className="text-xs font-bold text-[#D4AF37] uppercase tracking-[0.3em] flex items-center gap-2">
                    <Cpu className="w-4 h-4" />
                    Forensic Scanner Controls
                  </h2>
                  <p className="text-xs text-white/40 mt-1 font-light">
                    Multi-threaded parser for TXT, JSON, CSV, XML, and Logs with SHA-256 incremental caching and 15-line sliding context window.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleTriggerScan(false)}
                    disabled={loading}
                    className="px-6 py-3 bg-white text-black font-bold text-[11px] uppercase tracking-[0.2em] hover:bg-[#D4AF37] transition-colors rounded-none flex items-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5" />
                    Incremental Scan
                  </button>
                  <button
                    onClick={() => handleTriggerScan(true)}
                    disabled={loading}
                    className="px-6 py-3 border border-white/20 text-white font-bold text-[11px] uppercase tracking-[0.2em] hover:border-white transition-colors bg-transparent rounded-none flex items-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    Force Full Rescan
                  </button>
                  <button
                    onClick={handleGenerateSamples}
                    disabled={loading}
                    className="px-6 py-3 border border-[#D4AF37]/50 text-[#D4AF37] font-bold text-[11px] uppercase tracking-[0.2em] hover:bg-[#D4AF37] hover:text-black transition-colors bg-transparent rounded-none flex items-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    Generate Samples & Reindex
                  </button>
                </div>
              </div>

              {/* Progress Panel */}
              <div className="bg-[#080808] p-5 border border-white/10 space-y-4 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-white/40 tracking-wider">
                    ENGINE STATUS:{' '}
                    <strong className="text-[#D4AF37] uppercase">{scannerProgress.status}</strong>
                  </span>
                  <span className="text-white font-bold tracking-widest">{scannerProgress.progress_pct}%</span>
                </div>
                {/* Hairline Gold Progress Bar */}
                <div className="w-full h-[2px] bg-white/10 relative overflow-hidden">
                  <div
                    className="h-full bg-[#D4AF37] transition-all duration-300"
                    style={{ width: `${scannerProgress.progress_pct}%` }}
                  ></div>
                </div>
                <div className="flex flex-wrap items-center justify-between text-[11px] text-white/40 pt-1">
                  <span>Current: <strong className="text-white/70">{scannerProgress.current_file || 'Idle'}</strong></span>
                  <span>
                    Files: {scannerProgress.files_scanned} / {scannerProgress.total_files} | Entities: <strong className="text-[#D4AF37]">{scannerProgress.entities_found}</strong>
                  </span>
                </div>
              </div>
            </div>

            {/* Architecture Card */}
            <div className="p-6 bg-[#0C0C0C] border border-white/10 space-y-4 text-xs">
              <h3 className="text-xs uppercase tracking-[0.3em] text-[#D4AF37] font-bold flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Air-Gapped Forensic Architecture Integrity
              </h3>
              <ul className="space-y-2 text-white/50 list-none pl-0">
                <li className="flex items-start gap-2">
                  <span className="text-[#D4AF37]">•</span> Zero external telemetry: no DNS resolutions, no HTTP egress calls, no external models.
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#D4AF37]">•</span> SQLite WAL mode with multi-column indexed queries for 500+ container capacity.
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#D4AF37]">•</span> Normalized entities across 15 high-speed regex & checksum detectors with exact confidence weighting.
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#D4AF37]">•</span> Record clustering merges adjacent forensic findings into unified threat actor and identity profiles.
                </li>
              </ul>
            </div>
          </div>
        )}

        {/* TAB 4: AUDIT LOGS & EXPORT */}
        {activeTab === 'audit' && (
          <div className="space-y-6">
            <div className="p-6 bg-[#0C0C0C] border border-white/10 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-xs font-bold text-[#D4AF37] uppercase tracking-[0.3em] flex items-center gap-2">
                  <Download className="w-4 h-4" />
                  Forensic Incident Export
                </h2>
                <p className="text-xs text-white/40 mt-1 font-light">
                  Download immutable JSON report containing container metadata, detector metrics, indexed record clusters, and audit trail.
                </p>
              </div>
              <button
                onClick={handleExportFullReport}
                className="px-6 py-3 bg-white text-black font-bold text-[11px] uppercase tracking-[0.2em] hover:bg-[#D4AF37] transition-colors rounded-none flex items-center gap-2 cursor-pointer"
              >
                <Download className="w-4 h-4" />
                Export Full Audit JSON Report
              </button>
            </div>

            {/* Audit Log Table */}
            <div className="p-6 bg-[#0C0C0C] border border-white/10 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase text-white/40 tracking-[0.2em] flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-[#D4AF37]" />
                  Immutable Local Investigation Audit Trail
                </h3>
                <button
                  onClick={loadAuditLogs}
                  className="text-xs font-mono uppercase tracking-wider text-white/40 hover:text-white flex items-center gap-1.5 cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" /> Refresh
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="text-[10px] text-white/40 uppercase tracking-[0.2em] bg-white/[0.02] border-b border-white/10">
                    <tr>
                      <th className="px-4 py-3 font-mono">Timestamp (UTC)</th>
                      <th className="px-4 py-3">Operator</th>
                      <th className="px-4 py-3">Action</th>
                      <th className="px-4 py-3 font-mono">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 font-mono text-[11px]">
                    {auditLogs.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="px-4 py-8 text-center text-white/40 uppercase tracking-wider">
                          No audit logs recorded yet.
                        </td>
                      </tr>
                    ) : (
                      auditLogs.map((log, idx) => (
                        <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                          <td className="px-4 py-2.5 text-white/40">{log.timestamp}</td>
                          <td className="px-4 py-2.5 text-[#D4AF37] font-semibold">{log.operator}</td>
                          <td className="px-4 py-2.5 text-white font-medium">{log.action}</td>
                          <td className="px-4 py-2.5 text-white/70 max-w-md truncate">
                            {typeof log.details === 'string' ? log.details : JSON.stringify(log.details)}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* CLUSTER MODAL INSPECTOR */}
        {selectedCluster && (
          <div className="fixed inset-0 bg-black/85 backdrop-blur-md flex items-center justify-center p-4 z-50">
            <div className="bg-[#0C0C0C] border border-white/15 max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl rounded-none">
              <div className="p-5 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Shield className="w-4 h-4 text-[#D4AF37]" />
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-[0.2em]">
                    Cluster Inspector: {selectedCluster.record_id}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedCluster(null)}
                  className="text-white/60 hover:text-white border border-white/20 text-[10px] uppercase tracking-widest px-3 py-1 bg-transparent hover:border-white cursor-pointer transition-colors"
                >
                  ✕ Close
                </button>
              </div>

              <div className="p-6 space-y-5 overflow-y-auto text-xs font-mono">
                <div>
                  <div className="text-[10px] text-white/40 uppercase tracking-[0.2em] mb-1.5">Primary Match Artifact</div>
                  <div className="p-4 bg-[#080808] border border-white/10 flex items-center justify-between">
                    <div>
                      <span className="text-[#D4AF37] font-bold text-base">
                        {selectedCluster.primary_match.raw_value}
                      </span>
                      <span className="ml-2.5 text-white/40 uppercase text-[10px]">
                        ({selectedCluster.primary_match.field_type})
                      </span>
                    </div>
                    <span className="px-2.5 py-0.5 bg-white/5 text-white/80 border border-white/10 text-[10px] uppercase tracking-wider">
                      Confidence: {selectedCluster.primary_match.confidence}
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-white/40 uppercase tracking-[0.2em] mb-1.5">All Correlated Identity Fields</div>
                  <div className="p-4 bg-[#080808] border border-white/10 space-y-2">
                    {Object.entries(selectedCluster.connected_fields).map(([k, v]) => (
                      <div key={k} className="flex gap-3">
                        <span className="text-white/40 w-44 shrink-0 uppercase text-[10px] tracking-wider">{k}:</span>
                        <span className="text-white font-medium break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-white/40 uppercase tracking-[0.2em] mb-1.5">Raw Evidence Provenance</div>
                  <div className="p-4 bg-[#080808] border border-white/10 space-y-2">
                    <div>Container: <strong className="text-white">{selectedCluster.primary_match.container_name}</strong></div>
                    <div>Source File: <strong className="text-[#D4AF37]">{selectedCluster.primary_match.source_file}</strong></div>
                    <div>Line: <strong className="text-white">{selectedCluster.primary_match.line_number}</strong></div>
                    <div className="pt-2 text-white/40 text-[10px] uppercase tracking-wider">Surrounding Context Window:</div>
                    <pre className="p-3 bg-black border border-white/10 text-[11px] text-white/80 whitespace-pre-wrap break-all font-mono">
                      {selectedCluster.primary_match.context_snippet}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="h-14 px-8 border-t border-white/10 bg-[#080808] flex items-center justify-between text-[10px] uppercase tracking-[0.2em] text-white/30 font-mono">
        <div>Local Forensic Data Correlation Workbench • Air-Gapped Operation</div>
        <div>Zero Cloud Egress • Local SQLite Engine</div>
      </footer>
    </div>
  );
}
