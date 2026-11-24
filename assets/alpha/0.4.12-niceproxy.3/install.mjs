import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { runNpm } from './lib/npm.mjs';

const args = process.argv.slice(2);
const option = (name) => args[args.indexOf(name) + 1];
const project = resolve(args.includes('--project') ? option('--project') : '.');
const framework = args.includes('--framework') ? option('--framework') : 'react';
if (!['react', 'qwik'].includes(framework)) throw new Error('--framework react или qwik');
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
    throw new Error(`Нет корректного архива ${name}`);
  const bytes = remote
    ? Buffer.from(await (await fetch(new URL(item.file, base))).arrayBuffer())
    : await readFile(join(resolve(source), item.file));
  if (`sha512-${createHash('sha512').update(bytes).digest('base64')}` !== item.integrity)
    throw new Error(`Неверная контрольная сумма ${name}`);
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
  'Обязательно прочитай и соблюдай ALPHA_UI_AGENT_RULES.md. При нехватке компонента сообщи пользователю и создай или обнови ui-unspec/<component_name>.md с требованиями к универсальному компоненту.';
const legacyRule =
  'Обязательно прочитай и соблюдай ALPHA_UI_AGENT_RULES.md. При нехватке компонента сообщи пользователю и обнови ALPHA_UI_GAPS.md.';
const nextAgents = agents.includes(legacyRule)
  ? agents.replace(legacyRule, agentRule)
  : agents.includes('ALPHA_UI_AGENT_RULES.md')
    ? agents
    : agents + '\n' + agentRule + '\n';
if (nextAgents !== agents) await writeFile(agentFile, nextAgents);
console.log(
  `Установлена Alpha's UI ${manifest.version}. Инструкция для агентов подключена в AGENTS.md.`,
);
