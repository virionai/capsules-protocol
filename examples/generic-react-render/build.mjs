import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { buildExampleCapsule, FIXED_CREATED_AT } from "../lib/example-kit.mjs";

const items = [
  { label: "Template", value: "React-authored static render" },
  { label: "Runtime", value: "No browser dependency" },
  { label: "Portability", value: "Open the HTML directly" },
];

function WorkProduct({ title, items }) {
  return React.createElement(
    "section",
    { className: "panel" },
    React.createElement("h1", null, title),
    React.createElement("p", null, "This static work product was rendered from a React component at build time."),
    React.createElement(
      "dl",
      null,
      ...items.flatMap((item) => [
        React.createElement("dt", { key: `${item.label}-dt` }, item.label),
        React.createElement("dd", { key: `${item.label}-dd` }, item.value),
      ]),
    ),
  );
}

const markup = renderToStaticMarkup(
  React.createElement(WorkProduct, { title: "Generic React Render", items }),
);

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Generic React Render</title>
  <style>
    body{font-family:Arial,sans-serif;margin:32px;background:#fff;color:#172026}
    .panel{max-width:720px;margin:0 auto;border:1px solid #d9e0e5;border-radius:6px;padding:24px}
    h1{margin:0 0 10px;font-size:26px}
    dl{display:grid;grid-template-columns:140px 1fr;gap:10px 16px;margin-top:22px}
    dt{font-weight:700}dd{margin:0}
  </style>
</head>
<body>
${markup}
</body>
</html>`;

await buildExampleCapsule({
  id: "generic-react-render",
  title: "Generic React Render",
  summary: "React-authored static HTML work product",
  program: `# Generic React Render

This capsule carries static HTML rendered from a small React component at
build time. The packed work product is plain HTML with no browser-side
React dependency.

- Work product: \`payload/workproduct/react-render.html\`
- Data: \`payload/data/react-render.json\`

No warranty: this example is illustrative only and is not production,
legal, compliance, security, or operational guidance.
`,
  workproducts: { "react-render.html": html },
  payloads: [
    { path: "payload/data/react-render.json", content: `${JSON.stringify({ items }, null, 2)}\n` },
  ],
  events: [
    {
      actor: "human:originator",
      kind: "observation",
      action: "created_component_data",
      target: "payload/data/react-render.json",
      timestamp: FIXED_CREATED_AT,
      payload: { summary: "Created generic data for static render." },
    },
    {
      actor: "tool:renderer",
      kind: "observation",
      action: "rendered_react_workproduct",
      target: "payload/workproduct/react-render.html",
      timestamp: "2026-05-21T12:00:03Z",
      payload: { summary: "Rendered static HTML from React component." },
    },
  ],
});
