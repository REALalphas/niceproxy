import { spawn } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';

export function npmCli() {
  if (process.env.npm_execpath?.endsWith('.js')) return process.env.npm_execpath;
  const candidates = [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')];
  try {
    const paths = execFileSync(process.platform === 'win32' ? 'where.exe' : 'which', ['npm'], {
      encoding: 'utf8',
    })
      .trim()
      .split(/\r?\n/);
    candidates.push(...paths.map((p) => join(dirname(p), 'node_modules/npm/bin/npm-cli.js')));
    // npm is commonly a symlink (including version-manager installations).
    candidates.push(...paths.map((p) => realpathSync(p)).filter((p) => p.endsWith('npm-cli.js')));
  } catch {}
  const found = candidates.find(existsSync);
  if (!found) throw new Error('Run via npm run or set npm_execpath to npm-cli.js.');
  return found;
}
export function runNpm(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [npmCli(), ...args], {
      ...options,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (b) => {
      output += b;
      options.onOutput?.(String(b));
    });
    child.stderr.on('data', (b) => {
      output += b;
      options.onOutput?.(String(b));
    });
    child.once('error', reject);
    child.once('exit', (code) =>
      code === 0
        ? resolve(output)
        : reject(new Error(`npm ${args[0]} exited with code ${code}\n${output.slice(-8000)}`)),
    );
  });
}
