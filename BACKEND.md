# Backend Setup

## 1) Configure Supabase
1. Create a Supabase project.
2. Run the SQL in `supabase/schema.sql`.
3. Copy the Project URL, the publishable/anon key, and the Service Role key.

## 2) Create `.env`
Copy `.env.example` to `.env` and fill in all values.

Candidate and admin password login uses `SUPABASE_ANON_KEY` (or a publishable key equivalent) for `signInWithPassword`.
If that key is missing, account creation can leave a partial auth-only user and later sign-ins will fail to sync correctly.

## 3) Install and run
```bash
npm install
npm run dev
```

The server runs at `http://localhost:4000` and serves the HTML files from the project root.
