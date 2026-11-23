// Run once:  node setup.js   -> prints fresh secrets to paste into Vercel (Settings > Environment Variables)
const r = () => require('crypto').randomBytes(32).toString('hex');
for (const n of ['PEPPER', 'ENCRYPTION_KEY', 'SESSION_SECRET', 'CRON_SECRET']) console.log(`${n}=${r()}`);
console.log('\nKeep these safe. If ENCRYPTION_KEY or PEPPER is lost or changed, existing accounts and backups cannot be read.');
