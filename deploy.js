// Sends your local .env settings to Vercel and deploys. Usage: node deploy.js [--dry]
const fs = require('fs'), { spawnSync } = require('child_process');
const dry = process.argv.includes('--dry');
if (!fs.existsSync('.env')) { console.error('No .env file found. Run start.bat once first, so your settings exist.'); process.exit(1); }
const env = Object.fromEntries(fs.readFileSync('.env', 'utf8').split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith('#')).map(l => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }).filter(([k, v]) => k && v));
const need = ['PEPPER', 'ENCRYPTION_KEY', 'SESSION_SECRET', 'CRON_SECRET', 'FIREBASE_SERVICE_ACCOUNT'];
const miss = need.filter(k => !env[k]); if (miss.length) { console.error('Missing in .env: ' + miss.join(', ')); process.exit(1); }
const names = [...need, ...['DB_PREFIX', 'AWS_REGION', 'S3_BUCKET', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'].filter(k => env[k])];
const vercel = (args, { input, quiet } = {}) => {
  if (dry) { console.log('vercel ' + args.join(' ') + (input !== undefined ? '   [value hidden]' : '')); return { status: 0 }; }
  return spawnSync('vercel', args, { input, shell: true, encoding: 'utf8', stdio: [input !== undefined ? 'pipe' : 'inherit', quiet ? 'ignore' : 'inherit', quiet ? 'ignore' : 'inherit'] });
};
if (vercel(['whoami'], { quiet: true }).status !== 0) { console.log('Please log in to Vercel (a browser window will open).'); if (vercel(['login']).status !== 0) process.exit(1); }
console.log('\nLinking this folder to a Vercel project...'); if (vercel(['link', '--yes']).status !== 0) { console.error('Could not link the project.'); process.exit(1); }
console.log('\nSending your settings (' + names.length + ' values) to Vercel...');
for (const n of names) { vercel(['env', 'rm', n, 'production', '--yes'], { quiet: true }); const r = vercel(['env', 'add', n, 'production'], { input: env[n], quiet: true }); console.log((r.status === 0 ? '  sent    ' : '  FAILED  ') + n); if (r.status !== 0) process.exit(1); }
console.log('\nDeploying...'); if (vercel(['--prod', '--yes']).status !== 0) process.exit(1);
console.log('\nDone. Last step: in vercel.com open your project > Settings > Deployment Protection and switch OFF "Vercel Authentication".');
