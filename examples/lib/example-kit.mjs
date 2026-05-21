import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CapsuleBuilder,
  CapsuleReader,
  generateEd25519,
  verifyCapsule,
} from "../../sdk-js/src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXAMPLES_ROOT = join(HERE, "..");
const enc = new TextEncoder();
const dec = new TextDecoder();

export const FIXED_CREATED_AT = "2026-05-21T12:00:00Z";
export const FIXED_SIGNED_AT = "2026-05-21T12:00:05Z";

export async function buildExampleCapsule({
  id,
  title,
  summary,
  program,
  workproducts,
  payloads = [],
  events,
}) {
  const originator = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "Example Originator" },
    participants: [
      { actor_id: "human:originator", role: "originator", label: "Example Originator" },
      { actor_id: "tool:renderer", role: "tool", label: "Example Renderer" },
    ],
    createdAt: FIXED_CREATED_AT,
  });

  builder.setProgram(program);
  builder.setAgents(`# Agents

- human:originator may create and sign this generic example capsule.
- tool:renderer may render generic work products from included data.

This example is illustrative only and carries no warranty.
`);

  builder.addSkill("generic-template", {
    json: {
      id: "generic-template",
      description: "Generic example template instructions.",
      version: "0.1.0",
    },
    markdown: `# Generic Template

Use the included work product as a portable example artifact. Do not treat
the example content as operational, legal, compliance, or security advice.
`,
    signed: true,
  });

  for (const [path, content] of Object.entries(workproducts)) {
    builder.addPayload(`payload/workproduct/${path}`, enc.encode(content));
  }
  for (const { path, content } of payloads) {
    builder.addPayload(path, typeof content === "string" ? enc.encode(content) : content);
  }
  for (const event of events) {
    builder.appendEvent(event);
  }

  const bytes = await builder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
    ],
    signedAt: FIXED_SIGNED_AT,
  });

  const outDir = join(EXAMPLES_ROOT, id, "output");
  await mkdir(outDir, { recursive: true });
  const capsulePath = join(outDir, `${id}.capsule`);
  await writeFile(capsulePath, Buffer.from(bytes));
  await writeFile(join(outDir, "originator-public-key.txt"), `${originator.publicKeyHex}\n`);

  console.log(`${id}: wrote ${capsulePath} (${bytes.length} bytes)`);
  console.log(`${id}: ${summary}`);
  return capsulePath;
}

export async function verifyExampleCapsule(id, expectedHtmlName) {
  const capsulePath = join(EXAMPLES_ROOT, id, "output", `${id}.capsule`);
  const bytes = await readFile(capsulePath);
  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, {
    allowlist: [reader.manifest().originator.public_key],
  });
  if (!result.ok) {
    throw new Error(`${id}: verification failed: ${result.errors.join("; ")}`);
  }

  const htmlPath = `payload/workproduct/${expectedHtmlName}`;
  const htmlBytes = reader.files_().get(htmlPath);
  if (!htmlBytes) throw new Error(`${id}: missing ${htmlPath}`);
  const html = dec.decode(htmlBytes);
  if (/https?:\/\//i.test(html) || /<script[^>]+src=/i.test(html)) {
    throw new Error(`${id}: ${htmlPath} must be self-contained`);
  }
  if (!reader.program()?.includes("No warranty")) {
    throw new Error(`${id}: program.md must include a no-warranty note`);
  }

  console.log(`${id}: PASS`);
}
