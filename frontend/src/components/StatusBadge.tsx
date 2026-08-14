export function StatusBadge({ allowed }: { allowed: boolean }) {
  return (
    <span className={`badge ${allowed ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: 11 }}>
      <span className="dot" />
      {allowed ? 'ALLOWED' : 'DENIED'}
    </span>
  );
}
