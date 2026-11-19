# Contributing to VantaForge

## Before opening a change

Run:

```sh
npm install
npm run check
git diff --check
```

Do not commit `node_modules`, Wrangler state, local environment files, API
keys, OAuth tokens, uploaded media, or generated credentials. AI provider keys
belong to the user settings flow and must never be placed in `.env` files or
server defaults.

Production code must not add mock provider responses, fake analytics, sample
uploads, or silent fallbacks. When a credential or provider capability is
missing, return an explicit blocked state with a setup action.
