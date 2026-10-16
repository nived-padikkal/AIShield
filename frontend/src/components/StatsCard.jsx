export default function StatsCard({ label, value, tone }) {
  return (
    <div className={`card card-${tone}`}>
      <div className="card-value">{value}</div>
      <div className="card-label">{label}</div>
    </div>
  );
}
