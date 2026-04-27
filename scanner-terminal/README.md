# Wraith Workbench Frontend

React frontend for Wraith v4. It now provides a public product home page, mode selection, an automated scan dashboard, a manual replay workbench, and the existing command terminal.

## Run

```bash
npm install
npm start
```

The app opens at `http://localhost:3000` and expects the Flask API at `http://127.0.0.1:5001`.

Override the API URL:

```bash
set REACT_APP_API_URL=http://127.0.0.1:5001
npm start
```

## Features

- Scan setup form for target URL, depth, timeout, and safety mode.
- Home page with Wraith capability overview and Start Scan flow.
- Manual or automated scan mode selection.
- Automated scan dashboard with KPI tiles, severity donut, matrix, category bars, and timeline.
- Auth profile inputs for anonymous, bearer, headers, cookies, and Playwright storage state paths.
- API import inputs for OpenAPI, Postman, HAR, and GraphQL schema files or URLs.
- Sequence workflow inputs for YAML/JSON workflow paths.
- Live progress panel fed by Socket.IO scan events.
- Corpus viewer for persisted requests, responses, and sanitized evidence details.
- Manual request replay that sends a request through the Flask API and saves sanitized evidence to the corpus.
- xterm command view for `scan`, `scanrepo`, `status`, and `download`.

## Verify

```bash
npm test -- --watchAll=false
npm run build
```
