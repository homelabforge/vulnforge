import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

// Strict Mode removed: React 18's double-mounting behavior in Strict Mode
// causes React Query's refetchInterval to be cancelled when mutations execute,
// preventing real-time polling during scans. This is a known issue with
// React Query + React 18 Strict Mode interaction.
ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
