FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    tshark curl build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV POETRY_VERSION=1.8.2
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

# 👇 Ils sont dispo grâce au contexte racine
COPY pyproject.toml poetry.lock* ./

# 👇 Copie les fichiers du module uniquement
COPY Python_wireshark/ ./Python_wireshark/

WORKDIR /app/Python_wireshark

RUN poetry config virtualenvs.create false \
    && poetry install --no-root --only main

CMD ["python", "app.py"]
