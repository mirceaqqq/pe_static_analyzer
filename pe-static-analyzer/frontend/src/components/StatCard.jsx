import React from "react";

export function StatCard({ label, value }) {
  return (
    <div className="card stat">
      <span className="muted">{label}</span>
      <h2>{value}</h2>
    </div>
  );
}
