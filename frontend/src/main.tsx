import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

declare const APP_VERSION: string;

// Strict Mode removed: React 18's double-mounting behavior in Strict Mode
// causes React Query's refetchInterval to be cancelled when mutations execute,
// preventing real-time polling during scans. This is a known issue with
// React Query + React 18 Strict Mode interaction.
ReactDOM.createRoot(document.getElementById("root")!).render(<App />);

// Register service worker for shell caching. The ?v=<version> query string
// makes the browser treat each release as a distinct SW script, which (a)
// triggers the update flow on every deploy and (b) gives the SW a stable
// per-release identifier for namespacing its caches. Without this, a
// hardcoded cache name produces the classic "white screen on restart" when
// chunk hashes change.
if ("serviceWorker" in navigator && import.meta.env.PROD) {
  window.addEventListener("load", () => {
    const swUrl = `/sw.js?v=${encodeURIComponent(APP_VERSION)}`;
    navigator.serviceWorker
      .register(swUrl)
      .then((registration) => {
        console.log("[PWA] Service Worker registered:", registration.scope);
        registration.addEventListener("updatefound", () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener("statechange", () => {
              if (
                newWorker.state === "installed" &&
                navigator.serviceWorker.controller
              ) {
                console.log("[PWA] New version available! Reload to update.");
              }
            });
          }
        });
      })
      .catch((error) => {
        console.error("[PWA] Service Worker registration failed:", error);
      });
  });
}
