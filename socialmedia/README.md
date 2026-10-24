# Gather

Gather is a small social-community prototype with an SQLite-backed sign-up and login flow.

## Requirements

- Node.js 22.5 or newer (the server uses Node's built-in `node:sqlite` module).

## Run locally

From this directory, run:

```sh
npm start
```

Then open <http://127.0.0.1:3000>. Accounts and sessions are stored in `data/gather.sqlite`. The `data/` directory is ignored by Git. Set `DATABASE_PATH` to choose another SQLite file, or `PORT` to use another port.

Passwords are stored as salted scrypt hashes. The server issues an HTTP-only, SameSite cookie for a seven-day session; it does not store plaintext passwords. Use HTTPS and set `NODE_ENV=production` when deploying so session cookies are marked Secure.
