import { defineConfig, loadEnv } from 'vite';

function splitHosts(value: string | undefined) {
  return (value ?? '')
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
}

export default defineConfig(({ mode }) => {
  // Vite does not expose .env values through process.env while it loads this
  // file. Read the full env set so the public panel domain works in dev too.
  const env = loadEnv(mode, process.cwd(), '');
  const allowedHosts = [
    ...splitHosts(env.NICEPROXY_DOMAIN),
    ...splitHosts(env.VITE_ALLOWED_HOSTS),
  ].filter((host, index, hosts) => hosts.indexOf(host) === index);

  return {
    base: './',
    ...(allowedHosts.length > 0 ? { server: { allowedHosts } } : {}),
  };
});
