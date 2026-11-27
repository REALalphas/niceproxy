import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { runNpm } from './lib/npm.mjs';

const args = process.argv.slice(2);
const option = (name) => args[args.indexOf(name) + 1];
const project = resolve(args.includes('--project') ? option('--project') : '.');
const framework = args.includes('--framework') ? option('--framework') : 'react';
if (!['react', 'qwik'].includes(framework)) throw new Error('--framework must be react or qwik');
const source = args.includes('--from') ? option('--from') : import.meta.dirname;
const remote = /^https?:/.test(source);
const base = remote ? new URL(source.endsWith('/') ? source : source + '/') : null;
const manifest = JSON.parse(
  remote
    ? await (await fetch(new URL('manifest.json', base))).text()
    : await readFile(join(resolve(source), 'manifest.json'), 'utf8'),
);
const cache = join(tmpdir(), `alpha-install-${randomUUID()}`);
await mkdir(cache, { recursive: true });
const files = [];
for (const name of ['@alpha/core', `@alpha/${framework}`, '@alpha/project-server']) {
  const item = manifest.packages[name];
  if (!item || !/^[a-zA-Z0-9._-]+\.tgz$/.test(item.file))
    throw new Error(`No valid archive for ${name}`);
  const bytes = remote
    ? Buffer.from(await (await fetch(new URL(item.file, base))).arrayBuffer())
    : await readFile(join(resolve(source), item.file));
  if (`sha512-${createHash('sha512').update(bytes).digest('base64')}` !== item.integrity)
    throw new Error(`Invalid checksum for ${name}`);
  const path = join(cache, item.file);
  await writeFile(path, bytes);
  files.push(path);
}
await runNpm(['install', '--save-exact', '--ignore-scripts', '--no-audit', '--no-fund', ...files], {
  cwd: project,
  onOutput: (t) => process.stdout.write(t),
});
const rules = remote
  ? await (await fetch(new URL('AGENTS.md', base))).text()
  : await readFile(join(resolve(source), 'AGENTS.md'), 'utf8');
await writeFile(join(project, 'ALPHA_UI_AGENT_RULES.md'), rules);
const agentFile = join(project, 'AGENTS.md');
let agents = '';
try {
  agents = await readFile(agentFile, 'utf8');
} catch {}
const agentRule =
  'Always read and follow ALPHA_UI_AGENT_RULES.md. If a component is missing, notify the user and create or update ui-unspec/<component_name>.md with requirements for a universal component.';
const legacyRule =
  '\u041e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u044c\u043d\u043e \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0439 \u0438 \u0441\u043e\u0431\u043b\u044e\u0434\u0430\u0439 ALPHA_UI_AGENT_RULES.md. \u041f\u0440\u0438 \u043d\u0435\u0445\u0432\u0430\u0442\u043a\u0435 \u043a\u043e\u043c\u043f\u043e\u043d\u0435\u043d\u0442\u0430 \u0441\u043e\u043e\u0431\u0449\u0438 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044e \u0438 \u043e\u0431\u043d\u043e\u0432\u0438 ALPHA_UI_GAPS.md.';
const nextAgents = agents.includes(legacyRule)
  ? agents.replace(legacyRule, agentRule)
  : agents.includes('ALPHA_UI_AGENT_RULES.md')
    ? agents
    : agents + '\n' + agentRule + '\n';
if (nextAgents !== agents) await writeFile(agentFile, nextAgents);
console.log(
  `Installed Alpha's UI ${manifest.version}. Agent instructions linked in AGENTS.md.`,
);
