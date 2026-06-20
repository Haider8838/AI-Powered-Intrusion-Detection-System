# API entrypoint for Vercel — expose the Flask app from server.py
# Vercel's Python runtime will use the `app` variable as the WSGI app.

from server import app  # server.py defines `app` and `socketio`

# Ensure the module exposes `app` (Flask) at import time. Vercel will call it.

__all__ = ["app"]
