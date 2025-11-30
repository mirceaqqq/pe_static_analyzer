# PE Static Analyzer Desktop UI (React + Vite + Electron)

## Quick start (dev)
```bash
cd frontend
npm install
npm run dev            # UI dev server (http://localhost:5173)
npm run electron       # electron shell (dev) - API la http://localhost:8000
```

## API backend
In folder root:
```bash
python -m uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

## Prod build (Electron)
```bash
npm run dist:win       # build UI + portable exe (Windows)
```

`VITE_API_URL` implicit http://localhost:8000; seteaza in `.env` daca e alt host/port.
