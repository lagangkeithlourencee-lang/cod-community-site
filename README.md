# Bisaya COD Community — Tailwind CLI build

This site now uses a compiled Tailwind stylesheet (`output.css`) instead of the
`cdn.tailwindcss.com` script, so there's no runtime compiler warning and no
extra JS download on page load.

## Files
- `index.html`   — the site
- `input.css`    — Tailwind's entry point (`@tailwind base/components/utilities`)
- `output.css`   — the compiled, minified stylesheet `index.html` links to
- `tailwind.config.js` — tells Tailwind to scan `index.html` for classes in use
- `package.json` — has the `tailwindcss` dev dependency

## If you edit index.html and add new Tailwind classes
Run this from this folder so the new classes get compiled into output.css:

```bash
npm install
npx tailwindcss -i input.css -o output.css --minify
```

Or for local development with auto-rebuild on save:

```bash
npx tailwindcss -i input.css -o output.css --watch
```

## Deploying via GitHub + Cloudflare Pages

1. **Push this folder to a GitHub repo.**
   ```bash
   git init
   git add .
   git commit -m "Initial site"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```

2. **In the Cloudflare dashboard:** go to **Workers & Pages → Create →
   Pages → Connect to Git**, pick this repo, then set:
   - **Build command:** `npm install && npm run build`
   - **Build output directory:** `/` (repo root)

   Cloudflare will run that command on every push, regenerating
   `output.css` fresh from `input.css` + whatever Tailwind classes are in
   `index.html` — you don't need to commit a rebuilt `output.css` yourself
   before pushing.

3. **Deploy.** Cloudflare gives you a `*.pages.dev` URL immediately; add a
   custom domain later under the project's **Custom domains** tab.

### The clan-application form (`/api/apply`)
That endpoint is a separate Cloudflare Worker (with D1), not part of this
Pages project. Deploy it on its own with [Wrangler](https://developers.cloudflare.com/workers/wrangler/),
then update the `action` URL in `index.html`'s form to point at it — right
now the form only simulates a response since no real endpoint exists yet.
