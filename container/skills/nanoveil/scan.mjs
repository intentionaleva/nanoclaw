#!/usr/bin/env node
/**
 * NanoVeil AI-layer runner.
 * Used by agents to scan a message through the full pipeline (DeBERTa + NER).
 *
 * Usage:
 *   node scan.mjs --text "Hello, my email is foo@bar.com"
 *   echo "some text" | node scan.mjs
 *   node scan.mjs --output --text "Response text" --mappings '{"[EMAIL_0]":"..."}'
 *
 * Exit codes:
 *   0  message is valid (may be sanitized — use .sanitized_prompt from stdout)
 *   1  message is blocked (.is_valid === false — do not process)
 *
 * Stdout: JSON result object (LLM Guard-compatible)
 * Stderr: errors only
 */

import { scanInputWithAI, scanOutput } from './scanner.mjs';

function parseArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      opts[key] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    }
  }
  return opts;
}

async function readStdin() {
  if (process.stdin.isTTY) return null;
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data.trim()));
  });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const stdinText = await readStdin();
  const text = opts.text ?? stdinText ?? '';

  if (!text) {
    process.stderr.write('No text provided. Use --text "..." or pipe via stdin.\n');
    process.exit(2);
  }

  try {
    if (opts.output) {
      const mappings = opts.mappings ? JSON.parse(opts.mappings) : {};
      const result = scanOutput(text, mappings);
      process.stdout.write(JSON.stringify(result) + '\n');
      process.exit(result.is_valid ? 0 : 1);
    } else {
      const scannerOpts = {};
      if (opts['max-chars']) scannerOpts.maxChars = Number(opts['max-chars']);
      if (opts['ban-keywords']) scannerOpts.banKeywords = opts['ban-keywords'].split(',');
      if (opts['ner-org'] === 'true') scannerOpts.nerOrg = true;
      const result = await scanInputWithAI(text, scannerOpts);
      process.stdout.write(JSON.stringify(result) + '\n');
      process.exit(result.is_valid ? 0 : 1);
    }
  } catch (err) {
    process.stderr.write(`NanoVeil error: ${err.message}\n`);
    process.exit(2);
  }
}

main();
