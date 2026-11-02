FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install curl for healthchecks and build essentials for psutil/scikit-learn
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x docker-entrypoint.sh

ENV SENTINEL_DATA=/app/data
ENV HOST=0.0.0.0
ENV PORT=8000
ENV SENTINEL_BEHIND_PROXY=1

EXPOSE 8000

CMD ["./docker-entrypoint.sh"]
