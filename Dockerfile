FROM python:3.13-slim

WORKDIR /app

# Installer les dépendances système pour psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier et installer les dépendances Python
COPY saas-immobilier-backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'app
COPY saas-immobilier-backend/app.py .

# Exposer le port
EXPOSE 8080

# Lancer l'app avec gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--workers", "4"]
