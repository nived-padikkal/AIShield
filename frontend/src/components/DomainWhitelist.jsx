import { useState } from "react";
import { addDomain, removeDomain } from "../api.js";

export default function DomainWhitelist({ domains, onChanged }) {
  const [domain, setDomain] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!domain.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      await addDomain(domain.trim().toLowerCase());
      setDomain("");
      onChanged?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (d) => {
    setError("");
    try {
      await removeDomain(d);
      onChanged?.();
    } catch (err) {
      setError(err.message);
    }
  };

  const empty = domains.length === 0;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Domain Whitelist</h2>
        <span className={`whitelist-state ${empty ? "state-off" : "state-on"}`}>
          {empty ? "filtering off" : "enforced"}
        </span>
      </div>

      <form className="check-form" onSubmit={submit}>
        <input
          className="input"
          type="text"
          placeholder="e.g. api.example.com or *.example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          disabled={busy}
        />
        <button className="btn btn-primary" type="submit" disabled={busy || !domain.trim()}>
          Add
        </button>
      </form>

      {error && <div className="banner banner-error">{error}</div>}

      {empty ? (
        <p className="muted">
          Whitelist is empty — domain filtering is disabled. Add a domain to only allow
          commands that post/pass data to it.
        </p>
      ) : (
        <>
          <p className="muted">
            Commands that post or pass data to a domain not on this list are disallowed.
            Wildcards like <code>*.example.com</code> cover all subdomains.
          </p>
          <ul className="domain-list">
            {domains.map((d) => (
              <li key={d.id} className="domain-chip">
                <span>{d.domain}</span>
                <button
                  className="chip-remove"
                  onClick={() => remove(d.domain)}
                  title={`Remove ${d.domain}`}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
