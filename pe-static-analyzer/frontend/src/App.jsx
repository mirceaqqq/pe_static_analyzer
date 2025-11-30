import React, { useEffect, useState } from "react";
import { analyzeFile, analyzePath, scanDir, yaraSync, getStatus } from "./api";
import { UploadCard } from "./components/UploadCard";
import { StatCard } from "./components/StatCard";
import { ResultCard } from "./components/ResultCard";

export default function App() {
  const [status, setStatus] = useState({ status: "unknown" });
  const [result, setResult] = useState(null);
  const [scanSummary, setScanSummary] = useState(null);
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState("");
  const [folderPath, setFolderPath] = useState("");
  const [localPath, setLocalPath] = useState("");
  const [toast, setToast] = useState("");

  useEffect(() => {
    refreshStatus();
  }, []);

  const refreshStatus = async () => {
    try {
      const data = await getStatus();
      setStatus(data);
    } catch (e) {
      setStatus({ status: "offline" });
    }
  };

  const onUpload = async (file) => {
    setBusy(true);
    setToast("Se incarca fisierul...");
    try {
      const data = await analyzeFile(file);
      setResult(data);
      setToast("Analiza finalizata");
    } catch (e) {
      setToast("Eroare la analiza");
    } finally {
      setBusy(false);
    }
  };

  const onAnalyzePath = async () => {
    if (!localPath) return;
    setBusy(true);
    setToast("Analiza path local...");
    try {
      const data = await analyzePath(localPath);
      setResult(data);
      setToast("Analiza finalizata");
    } catch (e) {
      setToast("Eroare analiza path");
    } finally {
      setBusy(false);
    }
  };

  const onScanFolder = async () => {
    if (!folderPath) return;
    setBusy(true);
    setToast("Scanare folder...");
    try {
      const data = await scanDir(folderPath, true);
      setScanSummary({ count: data.count });
      setToast("Scanare finalizata");
    } catch (e) {
      setToast("Eroare scanare");
    } finally {
      setBusy(false);
    }
  };

  const onYaraSync = async () => {
    setBusy(true);
    setToast("Sync YARA...");
    try {
      const data = await yaraSync(token);
      setToast(`Sync ok: +${data.saved}`);
    } catch (e) {
      setToast("Eroare YARA sync");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <header className="hero">
        <div>
          <h1>PE Static Analyzer</h1>
          <p>Client React peste API-ul FastAPI (analiza executabile, scan, YARA sync)</p>
        </div>
        <div className="chips">
          <span className={`chip ${status.status === "ok" ? "chip-good" : "chip-bad"}`}>API: {status.status}</span>
          {busy && <span className="chip chip-warn">Busy</span>}
          {toast && <span className="chip chip-info">{toast}</span>}
        </div>
      </header>

      <section className="grid">
        <UploadCard onUpload={onUpload} busy={busy} />
        <div className="card">
          <h3>Analizeaza fisier local (cale)</h3>
          <input
            type="text"
            placeholder="C:\\path\\to\\file.exe"
            value={localPath}
            onChange={(e) => setLocalPath(e.target.value)}
          />
          <button disabled={busy} onClick={onAnalyzePath}>
            Analizeaza path
          </button>
        </div>
        <div className="card">
          <h3>Scanare folder</h3>
          <input
            type="text"
            placeholder="C:\\path\\to\\folder"
            value={folderPath}
            onChange={(e) => setFolderPath(e.target.value)}
          />
          <button disabled={busy} onClick={onScanFolder}>
            Scaneaza recursiv
          </button>
          {scanSummary && <p className="muted">Fisiere scanate: {scanSummary.count}</p>}
        </div>
        <div className="card">
          <h3>YARA Sync</h3>
          <input
            type="text"
            placeholder="GitHub token (optional)"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <button disabled={busy} onClick={onYaraSync}>
            Sync YARA
          </button>
        </div>
      </section>

      <section className="grid stats">
        <StatCard label="Risk" value={result?.risk_level || "--"} />
        <StatCard label="Score" value={result?.suspicion_score?.toFixed(1) || "--"} />
        <StatCard label="YARA" value={result?.yara_matches?.length ?? "--"} />
        <StatCard label="Time" value={result?.analysis_duration ? `${result.analysis_duration.toFixed(2)}s` : "--"} />
      </section>

      {result && <ResultCard result={result} />}
    </div>
  );
}
