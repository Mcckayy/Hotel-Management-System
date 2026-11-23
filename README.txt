HOTELDESK - hotel management system (Vercel + Google Firestore + AWS S3)

ROLES: Hotel Manager (full control), Receptionist (guests and bookings), Housekeeping (room status), Accountant (payments, no guest contact details).
The FIRST account created becomes the Hotel Manager. After that the manager adds every other staff member (Staff page).

A. Firebase (database) - use an EMPTY project
 1. console.firebase.google.com > Add project > Build > Firestore Database > Create database (Standard, production mode).
 2. Project settings > Service accounts > Generate new private key. Keep the .json file.

B. AWS S3 (backups)
 3. aws.amazon.com > S3 > Create bucket (name e.g. hoteldesk-backups-yourname, keep "Block all public access" ON, turn on Bucket Versioning).
 4. IAM > Users > Create user > attach this inline policy (replace BUCKET), then create an access key:
    { "Version": "2012-10-17", "Statement": [
      { "Effect": "Allow", "Action": ["s3:PutObject","s3:GetObject","s3:DeleteObject"], "Resource": "arn:aws:s3:::BUCKET/backups/*" },
      { "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::BUCKET" } ] }
    (Least privilege: this user can only touch the backups folder of this one bucket.)

C. Secrets
 5. In this folder run:  node setup.js    (prints PEPPER, ENCRYPTION_KEY, SESSION_SECRET, CRON_SECRET)

D. Vercel
 6. npm install -g vercel ; vercel login ; vercel   (create a NEW project, accept the defaults)
 7. Vercel > project > Settings > Environments > Production: add
      PEPPER, ENCRYPTION_KEY, SESSION_SECRET, CRON_SECRET     (from step 5)
      FIREBASE_SERVICE_ACCOUNT                                (all text of the .json file)
      AWS_REGION (e.g. eu-west-1), S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    Settings > Deployment Protection: switch off Vercel Authentication.
 8. vercel --prod  -> open the link -> "First-time setup" -> create the manager account.
 9. Staff page: add 3 more people (one per role) so all four roles exist. They set their own password and 2FA on first sign-in.

Backups run daily at 03:00 UTC (also "Back up now"). A restore point restores configuration only (staff, roles, archive, room rates), never bookings or guest data.
Never share the .json file, the AWS keys or your secrets.

RUN ON YOUR OWN PC (Windows)
 1. Install Node.js LTS. Unzip this folder. Have your Firebase key .json file ready (step A2 above, empty Firebase project).
 2. Double-click start.bat. The first time it installs, then asks you to drag the key file into the window and press Enter.
 3. Your browser opens http://localhost:3000. Next time, just double-click start.bat. Close the window to stop.

EASIEST WAY TO DEPLOY TO VERCEL (Windows)
 1. Run start.bat once (it creates your .env settings), then close it.
 2. Double-click deploy-vercel.bat. It logs you in to Vercel, creates the project, sends your settings, and deploys.
 3. On vercel.com open the project > Settings > Deployment Protection > switch OFF Vercel Authentication.
 4. Open the link it printed. Your online system uses the same database and secrets as your PC version.
