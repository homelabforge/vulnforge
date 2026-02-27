/**
 * About Page - Application information and credits
 */

import { useEffect, useState } from "react";
import { Shield, Database, Bell, Sparkles, Heart, CheckCircle, ExternalLink } from "lucide-react";
import { systemApi } from "../lib/api";

export function About() {
  const [version, setVersion] = useState<string>("...");

  useEffect(() => {
    systemApi.getAppInfo().then((info) => setVersion(info.version)).catch(() => setVersion("unknown"));
  }, []);

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Hero */}
      <div className="text-center">
        <div className="inline-flex items-center justify-center w-20 h-20 bg-blue-600/10 rounded-2xl mb-6">
          <Shield className="w-12 h-12 text-blue-500" />
        </div>
        <h1 className="text-4xl font-bold text-vuln-text mb-3">VulnForge</h1>
        <p className="text-xl text-vuln-text-muted">Container security insights for your homelab</p>
        <div className="mt-4 inline-block px-4 py-2 bg-blue-500/10 border border-blue-500/20 rounded-full">
          <span className="text-blue-500 font-semibold">v{version}</span>
        </div>
      </div>

      {/* What is VulnForge */}
      <div className="bg-vuln-surface rounded-lg border border-vuln-border p-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-4">What is VulnForge?</h2>
        <p className="text-vuln-text-muted leading-relaxed mb-4">
          VulnForge is a comprehensive, self-hosted container security dashboard designed for homelab
          operators who want actionable visibility into their stack. It combines Trivy (for
          vulnerabilities and misconfigurations), a native compliance checker, and Dive (for image
          efficiency) to surface security issues in one place—without relying on external SaaS services.
        </p>
        <p className="text-vuln-text-muted leading-relaxed">
          Built with reliability and clarity for home environments in mind: simple deployment, a
          lightweight SQLite datastore, offline-friendly scanners, and tooling that explains what to fix
          next. Whether you are running a single-node lab or a rack of services, VulnForge turns nightly
          scans into actionable chores instead of noisy reports.
        </p>
      </div>

      {/* Why VulnForge? */}
      <div className="bg-vuln-surface rounded-lg border border-vuln-border p-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-4">Why VulnForge?</h2>
        <div className="space-y-3 text-vuln-text-muted">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-500 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold text-vuln-text">Privacy First</p>
              <p className="text-sm">
                Self-hosted architecture means your data stays on your infrastructure. No cloud
                dependencies, no third-party data sharing, complete control over your information.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Database className="w-5 h-5 text-blue-500 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold text-vuln-text">Database-Backed Settings</p>
              <p className="text-sm">
                Configure everything through the UI with settings stored in SQLite. WAL persistence,
                backup/restore, CSV exports, and safety snapshots keep your security data accessible.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Bell className="w-5 h-5 text-blue-500 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold text-vuln-text">Multi-Service Notifications</p>
              <p className="text-sm">
                7 notification providers (ntfy, Gotify, Pushover, Slack, Discord, Telegram, Email)
                with per-event toggles and priority-based routing for security alerts.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-500 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold text-vuln-text">Comprehensive Security Coverage</p>
              <p className="text-sm">
                Trivy CVE scanning with CISA KEV tagging, CIS compliance checks, secret detection with
                triage workflow, and Dive layer analysis—all from a single dashboard.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Built with AI */}
      <div className="bg-vuln-surface rounded-lg border border-vuln-border p-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-4 flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-yellow-400" />
          Built with AI
        </h2>
        <p className="text-vuln-text-muted leading-relaxed mb-4">
          VulnForge is built through collaboration between human expertise and cutting-edge AI
          capabilities. Claude handles architecture design and full-stack development, Codex assists
          with bug fixing and security auditing, while the Operator guides product vision, requirements,
          and deployment strategy.
        </p>
        <ul className="space-y-2 text-vuln-text-muted text-sm">
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
            <span>
              <strong className="text-vuln-text">Claude</strong> – Full-stack architecture,
              feature development, and production-ready code delivery.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
            <span>
              <strong className="text-vuln-text">Operator</strong> – Product vision, requirements
              definition, homelab deployment expertise, and QA.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
            <span>
              <strong className="text-vuln-text">Codex</strong> – Bug fixing, security auditing,
              and code quality improvements.
            </span>
          </li>
        </ul>
      </div>

      {/* Learn More */}
      <div className="bg-vuln-surface rounded-lg border border-vuln-border p-6">
        <h2 className="text-2xl font-bold text-vuln-text mb-4">Learn More</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <a
            href="https://homelabforge.io/builds/vulnforge"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors text-sm font-medium"
          >
            <ExternalLink className="w-4 h-4" />
            Project Website
          </a>
          <a
            href="https://github.com/homelabforge/vulnforge"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors text-sm font-medium"
          >
            <ExternalLink className="w-4 h-4" />
            GitHub Repository
          </a>
        </div>
      </div>

      {/* Footer */}
      <div className="text-center pt-8 pb-8 border-t border-vuln-border">
        <p className="text-vuln-text-muted text-sm flex items-center justify-center gap-1">
          Made with <Heart className="w-4 h-4 text-red-500" /> for the homelab community
        </p>
        <p className="text-vuln-text-muted text-xs mt-2">
          VulnForge v{version}
        </p>
      </div>
    </div>
  );
}
