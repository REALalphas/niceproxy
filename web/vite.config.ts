import { defineConfig, loadEnv } from 'vite';
import { fileURLToPath } from 'node:url';

function splitHosts(value: string | undefined) {
  return (value ?? '')
    .split(',')
    .map((host) => host.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);
}

export default defineConfig(({ mode }) => {
  // Vite does not expose .env values through process.env while it loads this
  // file. The deployment .env lives beside the repository's compose file,
  // while this config is loaded with web/ as its working directory. Merge the
  // web-local values over the repository values so both documented layouts
  // configure the public panel domain.
  const webDir = fileURLToPath(new URL('.', import.meta.url));
  const repositoryDir = fileURLToPath(new URL('..', import.meta.url));
  const webEnv = loadEnv(mode, webDir, '');
  const repositoryEnv = loadEnv(mode, repositoryDir, '');
  const env = { ...repositoryEnv, ...webEnv };
  const allowedHosts = [
    ...splitHosts(env.NICEPROXY_DOMAIN),
    ...splitHosts(env.VITE_ALLOWED_HOSTS),
  ].filter((host, index, hosts) => hosts.indexOf(host) === index);

  return {
    base: './',
    ...(allowedHosts.length > 0 ? { server: { allowedHosts } } : {}),
  };
});
