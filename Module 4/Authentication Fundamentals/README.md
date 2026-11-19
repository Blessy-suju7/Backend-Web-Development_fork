# Authentication Fundamentals Starter

## Setup

```bash
npm install
cp .env.example .env
npm run db:push
npm start
```

Implement register and login behavior in the TODO-marked service functions. The SQLite datasource keeps local setup self-contained. Do not commit `.env` or `prisma/dev.db`.

## Endpoints

- `POST /auth/register`
- `POST /auth/login`

Registration accepts `{ "name", "email", "password" }`. Names are trimmed, emails are
trimmed and lowercased, and passwords must be at least 8 characters and no more than
72 UTF-8 bytes. A successful registration returns `201` with a safe `user` object;
invalid input returns `400`, and an existing email returns `409`.

Login accepts `{ "email", "password" }` and returns the same safe `user` object on
success. Missing users and incorrect passwords both return `401` with the same generic
error. Passwords are stored as bcrypt hashes and are never included in responses.
