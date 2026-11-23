// node setup.js              -> prints 4 fresh secrets (for Vercel)
// node setup.js --local      -> asks for your Firebase key file and creates .env (for running on your own PC)
// node setup.js path\key.json -> same, without asking
const fs = require('fs'), crypto = require('crypto'), readline = require('readline');
const r = () => crypto.randomBytes(32).toString('hex');
const vals = { PEPPER: r(), ENCRYPTION_KEY: r(), SESSION_SECRET: r(), CRON_SECRET: r() };
function create(keyFile) {
  if (fs.existsSync('.env')) { console.log('.env already exists, so it was not changed (replacing it would make existing accounts unreadable).'); return; }
  let key; try { key = JSON.parse(fs.readFileSync(keyFile, 'utf8')); if (!key.private_key) throw 0; } catch { console.error('\nThat file is not a Firebase service-account key (.json), or it could not be found.'); process.exit(1); }
  fs.writeFileSync('.env', Object.entries(vals).map(([k, v]) => `${k}=${v}`).join('\n') + '\nDB_PREFIX=hotel_\nFIREBASE_SERVICE_ACCOUNT=' + Buffer.from(JSON.stringify(key)).toString('base64') +
    '\n\n# Optional: AWS S3 backups (remove the # to switch on)\n# AWS_REGION=\n# S3_BUCKET=\n# AWS_ACCESS_KEY_ID=\n# AWS_SECRET_ACCESS_KEY=\n');
  console.log('\nSetup complete.');
}
const arg = process.argv[2];
if (arg === '--local') {
  if (fs.existsSync('.env')) process.exit(0);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question('\nDrag your Firebase key .json file into this window, then press Enter:\n> ', a => { rl.close(); create(a.trim().replace(/^["']+|["']+$/g, '')); });
} else if (arg) create(arg);
else { for (const [k, v] of Object.entries(vals)) console.log(`${k}=${v}`); console.log('\nKeep these safe. If ENCRYPTION_KEY or PEPPER is lost or changed, existing accounts and backups cannot be read.'); }
