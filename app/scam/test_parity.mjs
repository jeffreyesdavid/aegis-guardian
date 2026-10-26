// Checks that the browser rules (docs/app/rules.js) match scam_shield.py
// on every sample plus a few edge cases. Run: node app/scam/test_parity.mjs
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { scan } = require(join(here, "../../docs/app/rules.js"));

const lines = (f) => readFileSync(join(here, "samples", f), "utf8").split("\n").filter((l) => l.trim());
const messages = [
  ...lines("scams.txt"),
  ...lines("legit.txt"),
  "Text YES to +44 7700 900123 now",
  "Your Amazon order has shipped. Track it in the app.",
  "Hi mom just saying hi",
  "",
];

// One Python call scores every message, so non-zero verdict exit codes don't matter.
const pyCode = `import json,sys; sys.path.insert(0, sys.argv[1]); import scam_shield as ss
msgs=json.load(sys.stdin)
print(json.dumps([{"verdict":r.verdict,"score":r.score,"signals":r.signals} for r in map(ss.scan,msgs)]))`;
const run = spawnSync("python3", ["-c", pyCode, here], { input: JSON.stringify(messages), encoding: "utf8" });
if (run.status !== 0) { console.error(run.stderr); process.exit(1); }
const pyResults = JSON.parse(run.stdout);

let pass = 0, fail = 0;
messages.forEach((msg, i) => {
  const py = pyResults[i];
  const js = scan(msg);
  const same = py.verdict === js.verdict && py.score === js.score &&
    py.signals.map((s) => s.name).join() === js.signals.map((s) => s.name).join();
  if (same) pass++;
  else { fail++; console.log("MISMATCH:", JSON.stringify(msg).slice(0, 70), "\n  py:", py.verdict, py.score, "\n  js:", js.verdict, js.score); }
});
console.log(`parity: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
