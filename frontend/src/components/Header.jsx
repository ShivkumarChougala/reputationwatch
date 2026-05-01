export default function Header() {
  return (
    <header className="rw-header">
      <div className="rw-header-inner">
        <div className="rw-brand">
          <div className="rw-logo">RW</div>
          <span>ReputationWatch</span>
        </div>

        <nav className="rw-nav">
          <span className="active">IP Lookup</span>
          <span>Blocklist</span>
          <span>Intelligence</span>
          <span>API Docs</span>
          <span>Reports</span>
          <span>Pricing</span>
        </nav>

        <div className="rw-actions">
          <span className="rw-signin">Sign in</span>
          <button className="rw-button-primary">Get API Key</button>
        </div>
      </div>
    </header>
  );
}
