import { buildExampleCapsule, FIXED_CREATED_AT } from "../lib/example-kit.mjs";

const rows = [
  { name: "Alpha", category: "Input", score: 72 },
  { name: "Beta", category: "Review", score: 58 },
  { name: "Gamma", category: "Decision", score: 81 },
  { name: "Delta", category: "Follow-up", score: 43 },
];

const dashboardHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Generic Table And Graph</title>
  <style>
    body{font-family:Arial,sans-serif;margin:24px;color:#162129;background:#fff}
    main{max-width:820px;margin:0 auto}
    header{display:flex;justify-content:space-between;gap:16px;align-items:end}
    h1{font-size:24px;margin:0}
    button{border:1px solid #aeb8c2;background:#f6f8fa;border-radius:5px;padding:8px 10px}
    table{width:100%;border-collapse:collapse;margin-top:20px}
    th,td{border-bottom:1px solid #dbe1e6;padding:9px;text-align:left}
    th{background:#f4f6f8}
    svg{margin-top:20px;width:100%;height:180px;border:1px solid #dbe1e6;border-radius:6px}
    .bar{fill:#4f7cac}.label{font-size:12px;fill:#162129}
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>Generic Table And Graph</h1>
      <p>Self-contained browser work product. No external scripts.</p>
    </div>
    <button id="sort">Sort by score</button>
  </header>
  <table>
    <thead><tr><th>Name</th><th>Category</th><th>Score</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <svg id="chart" viewBox="0 0 400 180" role="img" aria-label="Score graph"></svg>
</main>
<script>
const data=${JSON.stringify(rows)};
let sorted=false;
function render(){
  const rows=sorted?[...data].sort((a,b)=>b.score-a.score):data;
  document.getElementById("rows").innerHTML=rows.map(r=>\`<tr><td>\${r.name}</td><td>\${r.category}</td><td>\${r.score}</td></tr>\`).join("");
  document.getElementById("chart").innerHTML=rows.map((r,i)=>{
    const x=30+i*90, h=r.score*1.45, y=150-h;
    return \`<rect class="bar" x="\${x}" y="\${y}" width="44" height="\${h}"></rect><text class="label" x="\${x}" y="168">\${r.name}</text><text class="label" x="\${x}" y="\${y-6}">\${r.score}</text>\`;
  }).join("")+'<line x1="20" y1="150" x2="380" y2="150" stroke="#162129"></line>';
}
document.getElementById("sort").addEventListener("click",()=>{sorted=!sorted;render();});
render();
</script>
</body>
</html>`;

await buildExampleCapsule({
  id: "generic-table-graph",
  title: "Generic Table And Graph",
  summary: "interactive table and graph work product",
  program: `# Generic Table And Graph

This capsule carries a small self-contained HTML work product with an
interactive table and graph.

- Work product: \`payload/workproduct/table-graph.html\`
- Data: \`payload/data/table-graph.json\`

No warranty: this example is illustrative only and is not production,
legal, compliance, security, or operational guidance.
`,
  workproducts: { "table-graph.html": dashboardHtml },
  payloads: [
    { path: "payload/data/table-graph.json", content: `${JSON.stringify({ rows }, null, 2)}\n` },
  ],
  events: [
    {
      actor: "human:originator",
      kind: "observation",
      action: "created_dataset",
      target: "payload/data/table-graph.json",
      timestamp: FIXED_CREATED_AT,
      payload: { summary: "Created generic table data." },
    },
    {
      actor: "tool:renderer",
      kind: "observation",
      action: "rendered_workproduct",
      target: "payload/workproduct/table-graph.html",
      timestamp: "2026-05-21T12:00:03Z",
      payload: { summary: "Rendered self-contained table and graph HTML." },
    },
  ],
});
