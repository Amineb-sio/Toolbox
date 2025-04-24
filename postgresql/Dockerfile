# Dockerfile

FROM python:3.10-slim

RUN apt-get update \
  && apt-get install -y curl build-essential \
  && apt-get clean

ENV POETRY_VERSION=1.8.2
RUN curl -sSL https://install.python-poetry.org | python3 - \
  && ln -s /root/.local/bin/poetry /usr/local/bin/poetry

# Important : le WORKDIR dans le contexte parent
WORKDIR /app

# On copie les fichiers Poetry (qui sont à la racine du build context maintenant)
COPY pyproject.toml poetry.lock* /app/

# Install des dépendances sans environnement virtuel local
RUN poetry config virtualenvs.create false \
  && poetry install --no-root --no-interaction --no-ansi

# Copie le code entier (sauf ce que .dockerignore exclut)
COPY . /app

CMD ["python", "main.py"]
