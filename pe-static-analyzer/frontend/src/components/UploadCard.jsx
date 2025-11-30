import React, { useState } from "react";

export function UploadCard({ onUpload, busy }) {
  const [drag, setDrag] = useState(false);

  const handleFile = (file) => {
    if (!file) return;
    onUpload(file);
  };

  return (
    <div
      className={`card upload ${drag ? "drag" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDrag(false);
        const file = e.dataTransfer.files[0];
        handleFile(file);
      }}
    >
      <h3>Upload & Analizeaza</h3>
      <p>Trage un fișier aici sau alege manual</p>
      <input
        type="file"
        accept=".exe,.dll,.sys"
        disabled={busy}
        onChange={(e) => handleFile(e.target.files[0])}
      />
      <button disabled={busy} onClick={() => document.querySelector('input[type="file"]').click()}>
        Selecteaza fisier
      </button>
    </div>
  );
}
