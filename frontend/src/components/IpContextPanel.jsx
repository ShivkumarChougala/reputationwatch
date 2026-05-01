export default function IpContextPanel({ data }) {
  const ctx = data?.context || {};

  const items = [
    { label: "Country", value: ctx.country || data?.country || "-" },
    { label: "City", value: ctx.city || data?.city || "-" },
    { label: "ASN", value: ctx.asn || data?.asn || "-" },
    { label: "ISP", value: ctx.isp || data?.isp || "-" },
    { label: "Organization", value: ctx.org || data?.org || "-" },
    { label: "Timezone", value: ctx.timezone || data?.timezone || "-" },
  ];

  return (
    <div className="rw-card">
      <h3>IP Context</h3>

      <div className="rw-context-grid">
        {items.map((item) => (
          <div key={item.label} className="rw-context-item">
            <span>{item.label}</span>
            <b>{item.value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}
