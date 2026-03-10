/**
 * VulnForge - Main Application with React Router
 */

import { lazy, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Link, useLocation, useNavigate } from "react-router-dom";
import { Shield, Home, Container, Key, Settings as SettingsIcon, Activity as ActivityIcon, FileCheck, LogOut, User } from "lucide-react";
import { Toaster } from "sonner";
import { PageSkeleton } from "@/components/LoadingSkeleton";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ThemeProvider, useTheme } from "@/contexts/ThemeContext";
import { SettingsProvider } from "@/contexts/SettingsContext";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { ProtectedRoute } from "@/components/ProtectedRoute";

// Lazy load page components for code splitting
const Dashboard = lazy(() => import("@/pages/Dashboard").then(m => ({ default: m.Dashboard })));
const Containers = lazy(() => import("@/pages/Containers").then(m => ({ default: m.Containers })));
const ContainerDetail = lazy(() => import("@/pages/ContainerDetail").then(m => ({ default: m.ContainerDetail })));
const Secrets = lazy(() => import("@/pages/Secrets").then(m => ({ default: m.Secrets })));
const Compliance = lazy(() => import("@/pages/Compliance").then(m => ({ default: m.Compliance })));
const Activity = lazy(() => import("@/pages/Activity").then(m => ({ default: m.Activity })));
const Settings = lazy(() => import("@/pages/Settings").then(m => ({ default: m.Settings })));
const About = lazy(() => import("@/pages/About").then(m => ({ default: m.About })));
const Login = lazy(() => import("@/pages/Login"));
const Setup = lazy(() => import("@/pages/Setup"));

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
  const navigate = useNavigate();
  const { theme } = useTheme();
  const { isAuthenticated, authMode, user, logout } = useAuth();

  const navigation = [
    { name: "Dashboard", shortName: "Home", path: "/", icon: Home },
    { name: "Containers", shortName: "Containers", path: "/containers", icon: Container },
    { name: "Secrets", shortName: "Secrets", path: "/secrets", icon: Key },
    { name: "Compliance", shortName: "Comply", path: "/compliance", icon: FileCheck },
    { name: "Activity", shortName: "Activity", path: "/activity", icon: ActivityIcon },
    { name: "Settings", shortName: "Settings", path: "/settings", icon: SettingsIcon },
  ];

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  const isActivePath = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <div className="min-h-screen bg-vuln-bg pb-16 md:pb-0 overflow-x-hidden">
      {/* Header */}
      <header className="bg-vuln-surface border-b border-vuln-border overflow-hidden">
        <div className="container mx-auto px-4 py-3 md:py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3">
              <Shield className="w-7 h-7 xl:w-9 xl:h-9 text-primary" />
              <div>
                <h1 className="text-xl xl:text-2xl font-bold text-primary">VulnForge</h1>
                <p className="text-xs xl:text-sm text-vuln-text-muted hidden xl:block">Container Vulnerability Scanner</p>
              </div>
            </Link>

            {/* Desktop Navigation — icons only at md, icons+labels at xl */}
            <nav className="hidden md:flex gap-1 items-center">
              {navigation.map((item) => {
                const Icon = item.icon;
                const isActive = isActivePath(item.path);
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    title={item.name}
                    className={`flex items-center gap-2 px-2 xl:px-3 py-2 rounded-lg text-sm transition-colors ${
                      isActive
                        ? "bg-primary text-white"
                        : "text-vuln-text-muted hover:text-vuln-text hover:bg-vuln-surface-light"
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="hidden xl:inline">{item.name}</span>
                  </Link>
                );
              })}
            </nav>

            {/* User/Logout - Desktop */}
            {isAuthenticated && authMode !== 'none' && (
              <div className="hidden md:flex items-center gap-2 ml-2 pl-2 border-l border-vuln-border">
                <div className="flex items-center gap-2 px-2 py-2 text-sm text-vuln-text-muted">
                  <User size={16} />
                  <span className="hidden xl:inline">{user?.username}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 px-2 py-2 rounded-md text-sm font-medium text-vuln-text-muted hover:bg-vuln-surface-light hover:text-vuln-text transition-colors"
                >
                  <LogOut size={16} />
                </button>
              </div>
            )}

            {/* Mobile Logout */}
            {isAuthenticated && authMode !== 'none' && (
              <button
                onClick={handleLogout}
                className="md:hidden flex items-center gap-1 px-2 py-2 rounded-md text-sm text-vuln-text-muted hover:bg-vuln-surface-light hover:text-vuln-text transition-colors"
              >
                <LogOut size={16} />
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-3 md:px-4 py-4">
        <Suspense fallback={<PageSkeleton />}>
          {children}
        </Suspense>
      </main>

      {/* Mobile Bottom Navigation */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 bg-vuln-surface border-t border-vuln-border z-40 h-14">
        <div className="flex justify-around items-center h-full">
          {navigation.map((item) => {
            const Icon = item.icon;
            const isActive = isActivePath(item.path);
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex flex-col items-center justify-center gap-0.5 py-1 min-w-[48px] flex-1 transition-colors ${
                  isActive
                    ? "text-primary bg-primary/10 rounded-lg"
                    : "text-vuln-text-muted"
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="text-[10px] leading-tight truncate">{item.shortName}</span>
              </Link>
            );
          })}
        </div>
      </nav>

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
            <AuthProvider>
              <BrowserRouter>
                <Routes>
                  {/* Public routes */}
                  <Route path="/login" element={<Suspense fallback={<PageSkeleton />}><Login /></Suspense>} />
                  <Route path="/setup" element={<Suspense fallback={<PageSkeleton />}><Setup /></Suspense>} />

                  {/* Protected routes */}
                  <Route
                    path="/*"
                    element={
                      <ProtectedRoute>
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
                      </ProtectedRoute>
                    }
                  />
                </Routes>
              </BrowserRouter>
            </AuthProvider>
          </ThemeProvider>
        </SettingsProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
