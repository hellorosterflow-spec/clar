import * as esbuild from 'esbuild';
import { copyFileSync, readFileSync } from 'node:fs';

await esbuild.build({
  entryPoints: ['src/key-local/main.js'],
  bundle: true,
  format: 'esm',
  outfile: 'assets/key-local.js',
  minify: true,
  legalComments: 'none',
  target: ['es2022'],
  logLevel: 'info',
});

copyFileSync('node_modules/pdfjs-dist/build/pdf.mjs', 'assets/pdfjs-parser.js');
copyFileSync('node_modules/pdfjs-dist/build/pdf.worker.min.mjs', 'assets/pdf.worker.min.js');

const bundled = readFileSync('assets/key-local.js', 'utf8');
if (!bundled.includes('pdfjs-parser.js') || !bundled.includes('pdf.worker.min.js')) {
  throw new Error('Bundle is missing the local PDF parser URLs.');
}
