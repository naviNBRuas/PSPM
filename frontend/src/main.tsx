import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import App from "./App";
import Dashboard from "./components/Dashboard";
import ImportPage from "./components/ImportPage";
import VaultItems from "./components/VaultItems";
import AnalysisReport from "./components/AnalysisReport";
import PasswordGenerator from "./components/PasswordGenerator";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<App />}>
          <Route index element={<Dashboard />} />
          <Route path="import" element={<ImportPage />} />
          <Route path="vault" element={<VaultItems />} />
          <Route path="analysis" element={<AnalysisReport />} />
          <Route path="generator" element={<PasswordGenerator />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
