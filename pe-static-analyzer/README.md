# PE Static Analyzer

A modular framework for static analysis of PE files (Portable Executables).

## Quick Start

```bash
pip install -r requirements.txt
python main.py --help
```

## Antivirus & Quarantine
- Rule engine: YARA (inclusiv sincronizare din GitHub cu `python main.py yara-sync --token <GITHUB_TOKEN>`).
- Politica de carantina: fisierele cu risc mare sunt mutate automat in `quarantine/` (config in `config/config.yaml`).
- Poti ajusta pragurile de risc/score/VT si daca fisierul original sa fie sters dupa copiere.

## Real-time AV (watcher)
- Porneste monitorizare: `python main.py watch C:/Users`
- Scanare recursiva: `python main.py scan-dir C:/path/to/folder`
- Update automat reguli YARA (optional, implicit on) in watcher; configurabil in `config/config.yaml` (sectiunea `watcher`).

## API + Frontend (React)
- API FastAPI: `uvicorn api:app --reload --host 0.0.0.0 --port 8000`
- Frontend React (Vite) in `frontend/`:
  - `cd frontend`
  - `npm install`
  - `npm run dev` (implicit VITE_API_URL=http://localhost:8000; seteaza in .env)
- Functionalitati UI: upload & analyze, analyze path local, scan folder, YARA sync, carduri risc/score, rezumat rezultat.

## Autostart la boot (Windows)
- Script dedicat: `scripts/install_watcher_task.ps1` (ruleaza ca Administrator).
- Creeaza un task programat care porneste watcher-ul la boot sub contul SYSTEM.
- Exemplu: `powershell -ExecutionPolicy Bypass -File scripts/install_watcher_task.ps1 -Paths "C:\Users" -IntervalMinutes 120`
- Stergere task: `Unregister-ScheduledTask -TaskName PEStaticAnalyzerWatcher -Confirm:$false`
