import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const result = await build({
    entryPoints: ['src/main.js'],
    bundle: true,
    format: 'iife',
    target: 'es2020',
    minify: true,
    write: false
});

const bundle = result.outputFiles[0].text;
const payload = `globalThis.__HE_BUNDLE__=${JSON.stringify(bundle)};\n${bundle}`;
const safePayload = payload.replaceAll('</script', '<\\/script');

const template = readFileSync('src/index.html', 'utf8');
if (!template.includes('/*__BUNDLE__*/')) {
    throw new Error('Bundle placeholder /*__BUNDLE__*/ not found in src/index.html');
}
const html = template.replace('/*__BUNDLE__*/', () => safePayload);

mkdirSync('dist', { recursive: true });
writeFileSync('dist/index.html', html);
console.log(`dist/index.html written (${(html.length / 1024).toFixed(1)} KiB)`);
