#!/usr/bin/env node
// replace-nav-block.js
//
// Replace the <nav>...</nav> block in an HTML file with a canonical block,
// optionally setting one nav link to .active. Designed to be idempotent +
// preserve every byte outside the nav block.
//
// Usage:
//   node scripts/replace-nav-block.js <htmlPath> <activeKey>
//
//   activeKey is one of: home | about | whitepaper | run-node | developers
//
// The script:
//   1. Reads the canonical nav template from scripts/_canonical-nav-subpage.html
//   2. Substitutes the active marker on the matching <a> tag
//   3. Replaces the <nav>...</nav> block in the target file
//   4. Verifies the output still parses (matching <nav>/</nav> count)
//   5. Writes the file in-place; aborts on any mismatch
//
// Refuses to run on index.html — that page has a different nav structure
// (Features / How It Works / Download anchors). Use index.html.bak-pre-1.2.177
// as the canonical for index.html instead.

const fs = require('node:fs');
const path = require('node:path');

const ARGS = process.argv.slice(2);
if (ARGS.length !== 2) {
  console.error('Usage: node replace-nav-block.js <htmlPath> <activeKey>');
  console.error('  activeKey: home | about | whitepaper | run-node | developers');
  process.exit(2);
}
const [htmlPath, activeKey] = ARGS;

if (path.basename(htmlPath) === 'index.html') {
  console.error('ERROR: refusing to operate on index.html — it has a different nav structure.');
  console.error('       Use the .bak-pre-1.2.177 file directly as the canonical index.');
  process.exit(2);
}

const ACTIVE_MAP = {
  home:        '__HOME_ACTIVE__',
  about:       '__ABOUT_ACTIVE__',
  whitepaper:  '__WHITEPAPER_ACTIVE__',
  'run-node':  '__RUNNODE_ACTIVE__',
  developers:  '__DEVELOPERS_ACTIVE__',
};
if (!(activeKey in ACTIVE_MAP)) {
  console.error('ERROR: unknown activeKey "' + activeKey + '"; valid: ' + Object.keys(ACTIVE_MAP).join(', '));
  process.exit(2);
}

// 1. Load the canonical nav template
const TEMPLATE_PATH = path.resolve(__dirname, '_canonical-nav-subpage.html');
let template = fs.readFileSync(TEMPLATE_PATH, 'utf8');

// 2. Substitute the active marker for the chosen page; strip the others
for (const [key, marker] of Object.entries(ACTIVE_MAP)) {
  if (key === activeKey) {
    // Replace the chosen marker with ` class="active"`
    template = template.split(marker).join(' class="active"');
  } else {
    // Strip all other markers (no class attribute on those links)
    template = template.split(marker).join('');
  }
}

// 3. Read target HTML
const original = fs.readFileSync(htmlPath, 'utf8');

// 4. Find the existing <nav>...</nav> block
const navRe = /<nav>[\s\S]*?<\/nav>/m;
const m = original.match(navRe);
if (!m) {
  console.error('ERROR: target file has no <nav>...</nav> block — refusing to insert one without manual review.');
  console.error('       File: ' + htmlPath);
  process.exit(3);
}

// 5. Substitute (the template already includes opening <nav> and closing </nav>)
// Strip the leading two-space indent from the template so it slots cleanly.
const newNav = template.replace(/\n\s*$/, '').replace(/^  /gm, '  ').trim();
const updated = original.replace(navRe, newNav);

// 6. Validate: exactly one <nav> and one </nav> in the output
const navOpens  = (updated.match(/<nav>/g) || []).length;
const navCloses = (updated.match(/<\/nav>/g) || []).length;
if (navOpens !== 1 || navCloses !== 1) {
  console.error('ERROR: post-substitution validation failed.');
  console.error('       <nav> count: ' + navOpens + ', </nav> count: ' + navCloses);
  process.exit(4);
}

// 7. Validate: no leftover __*_ACTIVE__ markers
if (/__[A-Z_]+_ACTIVE__/.test(updated)) {
  console.error('ERROR: leftover active-marker placeholder in output.');
  process.exit(4);
}

// 8. Validate: nav contains expected canonical links (no Open Wallet)
if (/Open Wallet/.test(updated.match(navRe)[0])) {
  console.error('ERROR: post-substitution nav still contains "Open Wallet" — refusing to write.');
  process.exit(4);
}
const expectedLinks = ['Home', 'Details', 'Whitepaper', 'Run a Node', 'Ion Swap', 'Developers'];
for (const link of expectedLinks) {
  if (!updated.match(navRe)[0].includes('>' + link + '<')) {
    console.error('ERROR: post-substitution nav missing expected link: ' + link);
    process.exit(4);
  }
}

// 9. Write
fs.writeFileSync(htmlPath, updated);
const beforeBytes = original.length;
const afterBytes = updated.length;
console.log('✓ nav block replaced in ' + path.basename(htmlPath));
console.log('  active: ' + activeKey);
console.log('  bytes: ' + beforeBytes + ' → ' + afterBytes + ' (delta ' + (afterBytes - beforeBytes) + ')');
