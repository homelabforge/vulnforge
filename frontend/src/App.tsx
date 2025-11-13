/**
 * VulnForge - Main Application with React Router
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { Shield, Home, Bug, Container, Key, Settings as SettingsIcon, Activity as ActivityIcon, FileCheck } from "lucide-react";
import { Toaster } from "sonner";
import { Dashboard } from "@/pages/Dashboard";
import { Vulnerabilities } from "@/pages/Vulnerabilities";
import { Containers } from "@/pages/Containers";
import { ContainerDetail } from "@/pages/ContainerDetail";
import { Secrets } from "@/pages/Secrets";
import { Compliance } from "@/pages/Compliance";
import { Activity } from "@/pages/Activity";
import { Settings } from "@/pages/Settings";
import { About } from "@/pages/About";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false, // Don't refetch when window regains focus
      refetchOnMount: true,        // Always refetch when component mounts
      refetchOnReconnect: true,    // Refetch when network reconnects
      staleTime: 0,                // Consider data always stale (important for polling)
      retry: 1,                    // Retry failed requests once
    },
  },
});

function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();

  const navigation = [
    { name: "Dashboard", path: "/", icon: Home },
    { name: "Containers", path: "/containers", icon: Container },
    { name: "Vulnerabilities", path: "/vulnerabilities", icon: Bug },
    { name: "Secrets", path: "/secrets", icon: Key },
    { name: "Compliance", path: "/compliance", icon: FileCheck },
    { name: "Activity", path: "/activity", icon: ActivityIcon },
    { name: "Settings", path: "/settings", icon: SettingsIcon },
  ];

  return (
    <div className="min-h-screen bg-[#0f1419]">
      {/* Header */}
      <header className="bg-[#1a1f2e] border-b border-gray-800">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-500" />
              <div>
                <h1 className="text-2xl font-bold text-blue-500">VulnForge</h1>
                <p className="text-sm text-gray-400">Container Vulnerability Scanner</p>
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
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                      isActive
                        ? "bg-blue-600 text-white"
                        : "text-gray-400 hover:text-white hover:bg-gray-700"
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {item.name}
                  </Link>
                );
              })}
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">{children}</main>

      {/* Toast Notifications */}
      <Toaster position="top-right" richColors />
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/containers" element={<Containers />} />
            <Route path="/containers/:id" element={<ContainerDetail />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/secrets" element={<Secrets />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/activity" element={<Activity />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
