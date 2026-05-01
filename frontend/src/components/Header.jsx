export default function Header() {
  return (
    <header className="rw-header">
      <div className="rw-brand">
        <div className="rw-logo">RW</div>
        <span>ReputationWatch</span>
      </div>

      <nav className="rw-nav">
        <span>IP Lookup</span>
        <span>Blocklist</span>
        <span>API Docs</span>
        <span>Reports</span>
      </nav>

      <button className="rw-button-outline">Get API Key</button>
    </header>
  );
}
