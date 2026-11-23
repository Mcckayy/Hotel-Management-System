SECURE PORTAL - deploy your own copy (Vercel + Google Firestore)

IMPORTANT: use YOUR OWN Firebase project, with an empty database. Your first account then becomes the admin.

A. Firebase (database)
 1. https://console.firebase.google.com > Add project.
 2. Build > Firestore Database > Create database (Standard edition, production mode, any location).
 3. Project settings (gear) > Service accounts > Generate new private key. Open the .json file in Notepad.

B. Secrets
 4. Install Node.js (LTS) from https://nodejs.org. Open a command window in this folder
    (type cmd in the folder's address bar) and run:  node setup.js
    Copy the 4 lines it prints (PEPPER, ENCRYPTION_KEY, SESSION_SECRET, CRON_SECRET).

C. Vercel
 5. Run:  npm install -g vercel     then:  vercel login     then:  vercel
    (Create a new project, accept the defaults.)
 6. On vercel.com > your project > Settings > Environments > Production, add:
      PEPPER, ENCRYPTION_KEY, SESSION_SECRET, CRON_SECRET   (the 4 values from step 4)
      FIREBASE_SERVICE_ACCOUNT                              (all text of the .json file)
    Settings > Deployment Protection: switch off Vercel Authentication.
 7. Run:  vercel --prod     then open the link it prints and create your account.

Backups run daily (03:00 UTC), encrypted, kept in Firestore (last 14).
Never share the .json file or your secrets, and don't reuse another person's.
