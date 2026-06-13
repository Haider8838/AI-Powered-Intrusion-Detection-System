FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap0.8-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt

COPY . /app

EXPOSE 5000

ENV PORT 5000

# Use Gunicorn with Eventlet for Socket.IO support in production
# Note: `server.py` creates `socketio = SocketIO(app)` at module level.
# Gunicorn worker will serve the Flask app; eventlet enables WebSocket support.
CMD ["sh","-c","gunicorn -k eventlet -w 1 server:app -b 0.0.0.0:${PORT:-5000}"]
