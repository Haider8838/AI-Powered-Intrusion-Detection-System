FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap0.8-dev \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY . /app
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 5000

ENV PORT 5000

# Use start.sh as the container entrypoint; it will optionally download model artefacts
# and then exec Gunicorn bound to the PORT environment variable.
CMD ["/start.sh"]
