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
      "Dockle image compliance dashboard with on-demand scans, pass/fail breakdowns, and remediation tips.",
      "Dive integration for layer efficiency analysis and wasted-byte insights per image.",
    ],
  },
  {
    title: "Automation for Homelabs",
    description: "Built to run quietly on your homelab while staying informative.",
    icon: Clock,
    points: [
      "Cron-style scheduling, automatic container discovery, and image batch scanning.",
      "ntfy-based notifications with rule builder, cooldowns, and templated alerts.",
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
  "Python 3.14 + FastAPI async backend",
  "SQLAlchemy 2.x ORM with SQLite (WAL mode)",
  "Docker SDK, APScheduler, and background task orchestration",
  "Trivy, Dockle, Dive CLI integrations",
  "ntfy / webhook notifications and CISA KEV enrichment",
];

const frontendStack = [
  "React 19 + TypeScript with Vite",
  "TanStack Query for server state and caching",
  "React Router v6 single-page navigation",
  "Tailwind CSS + tailwind-merge styling system",
  "Recharts, Lucide icons, and Sonner toasts",
];

const projectStats = [
  { label: "Lines of Code", value: "24k" },
  { label: "Python Backend", value: "16k" },
  { label: "TypeScript Frontend", value: "8k" },
  { label: "Containers Monitored", value: "55" },
];

export function About() {
  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="text-center mb-12">
        <div className="inline-flex items-center justify-center w-20 h-20 bg-blue-600/10 rounded-2xl mb-6">
          <Shield className="w-12 h-12 text-blue-500" />
        </div>
        <h1 className="text-4xl font-bold text-white mb-3">VulnForge</h1>
        <p className="text-xl text-gray-400">Container security insights for your homelab</p>
        <div className="mt-4 inline-block px-4 py-2 bg-green-500/10 border border-green-500/20 rounded-full">
          <span className="text-green-500 font-semibold">Version 2.7</span>
        </div>
      </div>

      {/* What is VulnForge */}
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-white mb-4">What is VulnForge?</h2>
        <p className="text-gray-300 leading-relaxed mb-4">
          VulnForge is a self-hosted dashboard that keeps homelab operators on top of container security.
          It combines Trivy, Docker Bench, Dockle, and Dive to surface vulnerabilities, configuration
          drift, and image hygiene issues in one place—all without relying on external SaaS services.
        </p>
        <p className="text-gray-300 leading-relaxed">
          The project focuses on reliability and clarity for home environments: simple deployment, a lightweight
          SQLite datastore, ntfy notifications, offline-friendly scanners, and tooling that explains what to fix next.
          Whether you are running a single-node lab or a rack of services, VulnForge turns nightly scans into actionable
          chores instead of noisy reports.
        </p>
      </div>

      {/* Key Features */}
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-white mb-6">Key Features</h2>
        <div className="space-y-4">
          {featureGroups.map(({ title, description, icon: Icon, points }, idx) => (
            <details
              key={title}
              className="group border border-gray-800/80 rounded-lg bg-[#111827]"
              {...(idx === 0 ? { open: true } : {})}
            >
              <summary className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between px-4 py-4 cursor-pointer select-none">
                <span className="flex items-center gap-3 text-white font-semibold">
                  <Icon className="w-5 h-5 text-blue-400" />
                  {title}
                </span>
                <span className="text-sm text-gray-400 md:text-right">{description}</span>
              </summary>
              <ul className="px-6 pb-5 space-y-3 text-sm text-gray-300">
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
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-white mb-6">Technology Stack</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
              <Code className="w-5 h-5 text-blue-500" />
              Backend
            </h3>
            <ul className="space-y-2 text-gray-400 text-sm">
              {backendStack.map((item) => (
                <li key={item} className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
              <Layers className="w-5 h-5 text-purple-500" />
              Frontend
            </h3>
            <ul className="space-y-2 text-gray-400 text-sm">
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
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8 mb-6">
        <h2 className="text-2xl font-bold text-white mb-6">Project Statistics</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          {projectStats.map(({ label, value }) => (
            <div key={label} className="text-center">
              <div className="text-3xl font-bold text-blue-400 mb-1">{value}</div>
              <div className="text-sm text-gray-400">{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Built with AI */}
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8">
        <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-yellow-400" />
          Built with AI
        </h2>
        <p className="text-gray-300 leading-relaxed mb-4">
          VulnForge has been shaped by a friendly trio: Claude kick-started the architecture and UI concepts,
          Codex (OpenAI GPT-5) continues to ship features, harden the stack, and tidy the codebase, and Jamey
          (oaniach) steers requirements, tests every homelab workflow, and brings the whole platform to life in
          production. It is very much an AI-assisted homelab project—with a human on-call.
        </p>
        <ul className="space-y-2 text-gray-300 text-sm">
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
        <p className="text-gray-500 text-sm">VulnForge v2.7 • Built with AI collaborators • November 2025</p>
        <p className="text-gray-600 text-xs mt-2">Deployed at vulnforge.starett.net</p>
      </div>
    </div>
  );
}
