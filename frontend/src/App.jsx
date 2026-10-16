import { useCallback, useEffect, useState } from "react";
import { clearHistory, getDomains, getHistory, getStats } from "./api.js";
import CommandChecker from "./components/CommandChecker.jsx";
import DomainWhitelist from "./components/DomainWhitelist.jsx";
import HistoryTable from "./components/HistoryTable.jsx";
import StatsCard from "./components/StatsCard.jsx";

export default function App() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [domains, setDomains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [s, h, d] = await Promise.all([getStats(), getHistory(), getDomains()]);
      setStats(s);
      setHistory(h);
      setDomains(d);
      setError("");
    } catch (err) {
      setError(`Cannot reach AiShield API: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleClear = async () => {
    await clearHistory();
    refresh();
  };

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>AiShield</h1>
          <p className="subtitle">Command screening dashboard — allow / disallow status</p>
        </div>
        <button className="btn btn-ghost" onClick={refresh} disabled={loading}>
          Refresh
        </button>
      </header>

      {error && <div className="banner banner-error">{error}</div>}

      <section className="stats-grid">
        <StatsCard label="Total Checks" value={stats?.total ?? 0} tone="total" />
        <StatsCard label="Allowed" value={stats?.allow ?? 0} tone="allow" />
        <StatsCard label="Needs Review" value={stats?.review ?? 0} tone="review" />
        <StatsCard label="Disallowed" value={stats?.disallow ?? 0} tone="disallow" />
      </section>

      <CommandChecker onChecked={refresh} />

      <DomainWhitelist domains={domains} onChanged={refresh} />

      <section className="panel">
        <div className="panel-header">
          <h2>Recent Decisions</h2>
          {history.length > 0 && (
            <button className="btn btn-ghost" onClick={handleClear}>
              Clear
            </button>
          )}
        </div>
        <HistoryTable rows={history} loading={loading} />
      </section>
    </div>
  );
}
