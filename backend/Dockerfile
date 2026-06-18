FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libpq-dev \
      libffi-dev \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libcairo2 \
      libgdk-pixbuf-xlib-2.0-0 \
      shared-mime-info \
      fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
