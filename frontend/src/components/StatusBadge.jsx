const TONES = {
  allow: "badge-allow",
  disallow: "badge-disallow",
  review: "badge-review",
  error: "badge-error",
};

const LABELS = {
  allow: "ALLOWED",
  disallow: "DISALLOWED",
  review: "REVIEW",
  error: "ERROR",
};

export default function StatusBadge({ status }) {
  const key = status || "review";
  return (
    <span className={`badge ${TONES[key] || "badge-review"}`}>
      {LABELS[key] || String(status).toUpperCase()}
    </span>
  );
}
