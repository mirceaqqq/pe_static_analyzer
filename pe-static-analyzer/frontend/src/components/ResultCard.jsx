import React from "react";

function KeyVal({ k, v }) {
  return (
    <div className="kv">
      <span className="muted">{k}</span>
      <span className="mono">{v}</span>
    </div>
  );
}

export function ResultCard({ result }) {
  if (!result) return null;
  return (
    <div className="card">
      <h3>Rezultat</h3>
      <div className="grid2">
        <KeyVal k="File" v={result.file_path} />
        <KeyVal k="Risk" v={result.risk_level} />
        <KeyVal k="Score" v={result.suspicion_score?.toFixed(1)} />
        <KeyVal k="Packer" v={result.packer_detected || "-"} />
        <KeyVal k="Heuristic flags" v={(result.heuristic_flags || []).length} />
        <KeyVal k="YARA matches" v={(result.yara_matches || []).length} />
        <KeyVal k="VT" v={result.vt_report?.detection_ratio || "-"} />
        <KeyVal k="Duration" v={`${result.analysis_duration?.toFixed(2)}s`} />
      </div>

      <div className="section">
        <h4>Hashes</h4>
        <div className="mono small">
          md5: {result.file_hash?.md5 || "-"}
          <br />
          sha256: {result.file_hash?.sha256 || "-"}
        </div>
      </div>

      {result.heuristic_flags?.length > 0 && (
        <div className="section">
          <h4>Heuristic flags</h4>
          <ul className="pill-list">
            {result.heuristic_flags.map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        </div>
      )}

      {result.yara_matches?.length > 0 && (
        <div className="section">
          <h4>YARA matches</h4>
          <ul className="pill-list">
            {result.yara_matches.slice(0, 10).map((m, i) => (
              <li key={i}>
                {m.rule} ({m.namespace})
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
