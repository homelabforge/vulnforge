/**
 * VulnForge - Main Application with React Router
 */

import { lazy, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { Shield, Home, Container, Key, Settings as SettingsIcon, Activity as ActivityIcon, FileCheck } from "lucide-react";
import { Toaster } from "sonner";
import { PageSkeleton } from "@/components/LoadingSkeleton";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ThemeProvider, useTheme } from "@/contexts/ThemeContext";
import { SettingsProvider } from "@/contexts/SettingsContext";

// Lazy load page components for code splitting
const Dashboard = lazy(() => import("@/pages/Dashboard").then(m => ({ default: m.Dashboard })));
const Containers = lazy(() => import("@/pages/Containers").then(m => ({ default: m.Containers })));
const ContainerDetail = lazy(() => import("@/pages/ContainerDetail").then(m => ({ default: m.ContainerDetail })));
const Secrets = lazy(() => import("@/pages/Secrets").then(m => ({ default: m.Secrets })));
const Compliance = lazy(() => import("@/pages/Compliance").then(m => ({ default: m.Compliance })));
const Activity = lazy(() => import("@/pages/Activity").then(m => ({ default: m.Activity })));
const Settings = lazy(() => import("@/pages/Settings").then(m => ({ default: m.Settings })));
const About = lazy(() => import("@/pages/About").then(m => ({ default: m.About })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false, // Don't refetch when window regains focus
      refetchOnMount: true,        // Always refetch when component mounts
      refetchOnReconnect: true,    // Refetch when network reconnects
      staleTime: 30000,            // 30s default - override per-query for real-time data
      retry: 1,                    // Retry failed requests once
    },
  },
});

function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const { theme } = useTheme();

  const navigation = [
    { name: "Dashboard", path: "/", icon: Home },
    { name: "Containers", path: "/containers", icon: Container },
    { name: "Secrets", path: "/secrets", icon: Key },
    { name: "Compliance", path: "/compliance", icon: FileCheck },
    { name: "Activity", path: "/activity", icon: ActivityIcon },
    { name: "Settings", path: "/settings", icon: SettingsIcon },
  ];

  return (
    <div className="min-h-screen bg-vuln-bg">
      {/* Header */}
      <header className="bg-vuln-surface border-b border-vuln-border">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-9 h-9 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-primary">VulnForge</h1>
                <p className="text-sm text-vuln-text-muted">Container Vulnerability Scanner</p>
              </div>
            </div>

            {/* Navigation */}
            <nav className="flex gap-2">
              {navigation.map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-base transition-colors ${
                      isActive
                        ? "bg-primary text-white"
                        : "text-vuln-text-muted hover:text-vuln-text hover:bg-vuln-surface-light"
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    {item.name}
                  </Link>
                );
              })}
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-4">
        <Suspense fallback={<PageSkeleton />}>
          {children}
        </Suspense>
      </main>

      {/* Toast Notifications - theme aware */}
      <Toaster position="top-right" richColors theme={theme} />
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <SettingsProvider>
          <ThemeProvider>
            <BrowserRouter>
              <Layout>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/containers" element={<Containers />} />
                  <Route path="/containers/:id" element={<ContainerDetail />} />
                  <Route path="/secrets" element={<Secrets />} />
                  <Route path="/compliance" element={<Compliance />} />
                  <Route path="/activity" element={<Activity />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/about" element={<About />} />
                </Routes>
              </Layout>
            </BrowserRouter>
          </ThemeProvider>
        </SettingsProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
