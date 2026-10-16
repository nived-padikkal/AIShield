import { useState } from "react";
import StatusBadge from "./StatusBadge.jsx";

export default function HistoryTable({ rows, loading }) {
  const [openId, setOpenId] = useState(null);

  if (loading) {
    return <p className="muted">Loading…</p>;
  }
  if (rows.length === 0) {
    return <p className="muted">No commands checked yet. Try one above.</p>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Command</th>
            <th>Detail</th>
            <th>Time (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Row
              key={row.id}
              row={row}
              open={openId === row.id}
              onToggle={() => setOpenId(openId === row.id ? null : row.id)}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ row, open, onToggle }) {
  const hasDetail = row.findings?.length > 0 || row.note;
  return (
    <>
      <tr className={open ? "row-open" : ""}>
        <td>
          <StatusBadge status={row.status} />
        </td>
        <td>
          <code>{row.command}</code>
        </td>
        <td>
          {hasDetail ? (
            <button className="btn btn-ghost btn-sm" onClick={onToggle}>
              {open ? "Hide" : "Show"}
            </button>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td className="time">{row.time.replace("T", " ").replace("+00:00", "")}</td>
      </tr>
      {open && (
        <tr className="detail-row">
          <td colSpan={4}>
            {row.note && <p className="result-note">{row.note}</p>}
            {row.findings?.length > 0 && (
              <ul className="findings">
                {row.findings.map((f, i) => (
                  <li key={i}>
                    <span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                    <span>
                      {f.why} <span className="mitre">({f.mitre})</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
