/**
 * About Page - Application information and credits
 */

import { Shield, CheckCircle, FileCheck, Clock, Database, Code, Layers, Sparkles } from "lucide-react";

const featureGroups = [
  {
    title: "Scanning & Detection",
    description: "Visibility into vulnerabilities and secrets across your stack.",
    icon: Shield,
    points: [
      "Trivy vulnerability scanning with KEV tagging, CVSS scoring, and comprehensive per-container history.",
      "Secret detection workflow with false-positive triage and accepted-risk tracking.",
      "Real-time scan progress, retry controls, and classified error guidance for every job.",
    ],
  },
  {
    title: "Compliance & Image Hygiene",
    description: "Keep images and hosts aligned with CIS best practices.",
    icon: FileCheck,
    points: [
      "Docker Bench scheduling with weekly reports, CSV export, and historical trend charts.",
      "Trivy misconfiguration scanning with on-demand scans, severity breakdowns, and remediation tips.",
      "Dive integration for layer efficiency analysis and wasted-byte insights per image.",
    ],
  },
  {
    title: "Automation for Homelabs",
    description: "Built to run quietly on your homelab while staying informative.",
    icon: Clock,
    points: [
      "Cron-style scheduling, automatic container discovery, and image batch scanning.",
      "Multi-service notifications (ntfy, Gotify, Pushover, Slack, Discord, Telegram, Email) with priority-based routing.",
      "Offline resilience with cached scanner databases, connectivity checks, and intelligent fallbacks.",
    ],
  },
  {
    title: "Data & Workflow",
    description: "All of your security data, preserved and easy to work with.",
    icon: Database,
    points: [
      "SQLite WAL persistence with backup/restore, download, and safety snapshots.",
      "CSV exports, drill-down findings, and timeline of homelab activity.",
      "Responsive dashboard widgets tuned for desktop dashboards and tablet control rooms.",
    ],
  },
];

const backendStack = [
  "Python 3.14 + FastAPI 0.121+ async backend",
  "SQLAlchemy 2.0+ ORM with SQLite (WAL mode)",
  "Docker SDK 7.1+, APScheduler 3.11+, and background task orchestration",
  "Trivy (vulnerabilities + misconfig), Docker Bench, Dive CLI integrations",
  "httpx 0.27+, ntfy/webhook notifications, and CISA KEV enrichment",
];

const frontendStack = [
  "React 19.2 + TypeScript 5.9 with Vite 7.2",
  "TanStack Query 5.90+ for server state and caching",
  "React Router 7.9+ single-page navigation",
  "Tailwind CSS 4.1+ with clsx and tailwind-merge",
  "Recharts 3.4+, Lucide icons 0.553+, and Sonner 2.0+ toasts",
];

const projectStats = [
  { label: "Lines of Code", value: "30.0k" },
  { label: "Python Backend", value: "18.8k" },
  { label: "TypeScript Frontend", value: "11.1k" },
  { label: "Notification Services", value: "7" },
];

export function About() {
  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="text-center mb-12">
        <div className="inline-flex items-center justify-center w-20 h-20 bg-blue-600/10 rounded-2xl mb-6">
          <Shield className="w-12 h-12 text-blue-500" />
        </div>
        <h1 className="text-4xl font-bold text-vuln-text mb-3">VulnForge</h1>
        <p className="text-xl text-vuln-text-muted">Container security insights for your homelab</p>
        <div className="mt-4 inline-block px-3 py-2 bg-blue-500/10 border border-blue-500/20 rounded-full">
          <span className="text-blue-500 font-semibold">Version 3.3.0</span>
        </div>
      </div>

      {/* What is VulnForge */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-4">What is VulnForge?</h2>
        <p className="text-vuln-text leading-relaxed mb-4">
          VulnForge is a self-hosted dashboard that keeps homelab operators on top of container security.
          It combines Trivy (for vulnerabilities and misconfigurations), Docker Bench (for host compliance),
          and Dive (for image efficiency) to surface security issues and configuration drift in one
          place—all without relying on external SaaS services.
        </p>
        <p className="text-vuln-text leading-relaxed">
          The project focuses on reliability and clarity for home environments: simple deployment, a lightweight
          SQLite datastore, ntfy notifications, offline-friendly scanners, and tooling that explains what to fix next.
          Whether you are running a single-node lab or a rack of services, VulnForge turns nightly scans into actionable
          chores instead of noisy reports.
        </p>
      </div>

      {/* Key Features */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-6">Key Features</h2>
        <div className="space-y-4">
          {featureGroups.map(({ title, description, icon: Icon, points }, idx) => (
            <details
              key={title}
              className="group border border-vuln-border/80 rounded-lg bg-vuln-surface"
              {...(idx === 0 ? { open: true } : {})}
            >
              <summary className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between px-4 py-4 cursor-pointer select-none">
                <span className="flex items-center gap-3 text-vuln-text font-semibold">
                  <Icon className="w-5 h-5 text-blue-400" />
                  {title}
                </span>
                <span className="text-sm text-vuln-text-muted md:text-right">{description}</span>
              </summary>
              <ul className="px-6 pb-5 space-y-3 text-sm text-vuln-text">
                {points.map((point) => (
                  <li key={point} className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
            </details>
          ))}
        </div>
      </div>

      {/* Technology Stack */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-6">Technology Stack</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h3 className="text-vuln-text font-semibold mb-3 flex items-center gap-2">
              <Code className="w-5 h-5 text-blue-500" />
              Backend
            </h3>
            <ul className="space-y-2 text-vuln-text-muted text-sm">
              {backendStack.map((item) => (
                <li key={item} className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-vuln-text font-semibold mb-3 flex items-center gap-2">
              <Layers className="w-5 h-5 text-purple-500" />
              Frontend
            </h3>
            <ul className="space-y-2 text-vuln-text-muted text-sm">
              {frontendStack.map((item) => (
                <li key={item} className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Statistics */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-6">Project Statistics</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          {projectStats.map(({ label, value }) => (
            <div key={label} className="text-center">
              <div className="text-3xl font-bold text-blue-400 mb-1">{value}</div>
              <div className="text-sm text-vuln-text-muted">{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Built with AI */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8">
        <h2 className="text-2xl font-bold text-vuln-text mb-4 flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-yellow-400" />
          Built with AI
        </h2>
        <p className="text-vuln-text leading-relaxed mb-4">
          VulnForge has been shaped by a friendly trio: Claude kick-started the architecture and UI concepts,
          Codex (OpenAI GPT-5) continues to ship features, harden the stack, and tidy the codebase, and Jamey
          (oaniach) steers requirements, tests every homelab workflow, and brings the whole platform to life in
          production. It is very much an AI-assisted homelab project—with a human on-call.
        </p>
        <ul className="space-y-2 text-vuln-text text-sm">
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
            <span>Claude 4.5 Sonnet – original blueprint, navigation structure, and first-pass styling.</span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
            <span>Codex (GPT-5) – ongoing refactors, scanner integrations, offline resilience, and UI polish.</span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
            <span>Jamey (oaniach) – maintainer, product direction, QA, documentation, and real-world deployment.</span>
          </li>
        </ul>
      </div>

      {/* Footer */}
      <div className="text-center mt-12 pb-8">
        <p className="text-vuln-text-disabled text-sm">VulnForge v3.3.0 • Built with AI collaborators • November 2025</p>
        <p className="text-vuln-text-disabled text-xs mt-2">Deployed at vulnforge.starett.net</p>
      </div>
    </div>
  );
}
