# Deploy to Vercel (Docker)

This document describes how to deploy the project to Vercel using the provided `Dockerfile` and `vercel.json`.

Prerequisites
- Vercel account
- Vercel CLI installed: `npm i -g vercel`
- (Optional) Docker installed to test locally

Files added
- `Dockerfile` — builds a Python 3.11 image and runs `python server.py` (respects `$PORT`).
- `vercel.json` — instructs Vercel to build the `Dockerfile` with `@vercel/docker`.
- `requirements.txt` — updated to include `gunicorn` and `eventlet`.

Quick deploy (interactive)
1. Login and deploy:

```bash
vercel login
cd path/to/project
vercel --prod
```

Follow prompts to choose scope and project name.

Local test with Docker
1. Build image:

```bash
docker build -t ai-ids .
```

2. Run container (bind host port 5000):

```bash
docker run --rm -p 5000:5000 -e PORT=5000 ai-ids
```

3. Check health:

```bash
curl http://localhost:5000/api/status
```

Environment variables to set in Vercel (Project → Settings → Environment Variables)
- `ANTHROPIC_API_KEY` — optional, enable Anthropic LLM features
- `GOOGLE_API_KEY` — optional, enable Gemini/Google GenAI features
- Any other secrets your deployment needs

Important caveats
- Packet capture features (scapy/raw sockets) require CAP_NET_RAW or equivalent and low-level network access; these features will likely be unavailable in Vercel-managed containers. The dashboard UI and prediction API will work, but live capture may be limited or non-functional.
- Model artefacts: the repository includes some joblib files. If missing, train the model via the dashboard (Settings → Train) or run `python server.py` locally to train and persist artefacts before deploying.

Optional: use Gunicorn + Eventlet
- The Dockerfile currently runs `python server.py`. If you prefer Gunicorn, you can change the CMD to run e.g.:

```bash
gunicorn -k eventlet -w 1 server:app -b 0.0.0.0:${PORT:-5000}
```

Note: Flask-SocketIO sometimes requires running via the `socketio.run(...)` entrypoint for full feature parity; the existing `server.py` uses `socketio.run` when executed directly. Keep this in mind if switching the entrypoint.

If you want, I can:
- Add a `README.md` snippet instead of this file, or
- Modify the `Dockerfile` to use a Gunicorn entrypoint and test the change locally.

---
Created to support deploying the AI-Powered IDS dashboard to Vercel using Docker.
