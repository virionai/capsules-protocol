import { buildExampleCapsule, FIXED_CREATED_AT } from "../lib/example-kit.mjs";

const metrics = [
  { label: "Inputs reviewed", value: 4 },
  { label: "Open items", value: 2 },
  { label: "Decisions logged", value: 3 },
];

const reportHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Generic Report Work Product</title>
  <style>
    body{font-family:Arial,sans-serif;margin:32px;color:#172026;background:#fff}
    main{max-width:760px;margin:0 auto}
    h1{font-size:28px;margin:0 0 8px}
    .meta{color:#59666f;margin-bottom:24px}
    .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}
    .card{border:1px solid #d7dde2;border-radius:6px;padding:14px}
    .value{font-size:26px;font-weight:700}
    table{width:100%;border-collapse:collapse;margin-top:18px}
    th,td{border-bottom:1px solid #d7dde2;padding:10px;text-align:left}
    th{background:#f4f6f8}
    svg{width:100%;height:130px;border:1px solid #d7dde2;border-radius:6px}
  </style>
</head>
<body>
<main>
  <h1>Generic Report</h1>
  <p class="meta">Template: report · Generated: ${FIXED_CREATED_AT}</p>
  <p>This portable work product summarizes a small set of neutral review items.</p>
  <section class="cards">
    ${metrics.map((m) => `<article class="card"><div class="value">${m.value}</div><div>${m.label}</div></article>`).join("")}
  </section>
  <svg role="img" aria-label="Small metric bar chart" viewBox="0 0 360 130">
    <rect x="32" y="50" width="56" height="52" fill="#4f8a8b"></rect>
    <rect x="152" y="76" width="56" height="26" fill="#c27c4a"></rect>
    <rect x="272" y="63" width="56" height="39" fill="#6d79a8"></rect>
    <line x1="20" y1="102" x2="340" y2="102" stroke="#172026"></line>
  </svg>
  <table>
    <thead><tr><th>Item</th><th>Status</th><th>Owner</th></tr></thead>
    <tbody>
      <tr><td>Scope confirmed</td><td>Done</td><td>Originator</td></tr>
      <tr><td>Evidence attached</td><td>Done</td><td>Renderer</td></tr>
      <tr><td>Follow-up questions</td><td>Open</td><td>Reviewer</td></tr>
    </tbody>
  </table>
</main>
</body>
</html>`;

await buildExampleCapsule({
  id: "generic-report",
  title: "Generic Report",
  summary: "static report work product",
  program: `# Generic Report

This capsule carries a small generic report work product.

- Work product: \`payload/workproduct/report.html\`
- Data: \`payload/data/report-metrics.json\`

No warranty: this example is illustrative only and is not production,
legal, compliance, security, or operational guidance.
`,
  workproducts: { "report.html": reportHtml },
  payloads: [
    {
      path: "payload/data/report-metrics.json",
      content: `${JSON.stringify({ metrics }, null, 2)}\n`,
    },
  ],
  events: [
    {
      actor: "human:originator",
      kind: "observation",
      action: "created_report",
      target: "program.md",
      timestamp: FIXED_CREATED_AT,
      payload: { summary: "Created generic report capsule." },
    },
    {
      actor: "tool:renderer",
      kind: "observation",
      action: "rendered_workproduct",
      target: "payload/workproduct/report.html",
      timestamp: "2026-05-21T12:00:03Z",
      payload: { summary: "Rendered static report HTML." },
    },
  ],
});
