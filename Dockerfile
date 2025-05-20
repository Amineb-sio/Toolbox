FROM python:3.10

WORKDIR /app

# Copier uniquement les fichiers Poetry pour éviter de réinstaller tout à chaque modification
COPY pyproject.toml poetry.lock ./

# Installer Poetry et les dépendances
RUN pip install poetry && poetry install --no-root

# Copier le reste du projet
COPY . .

# Exposer le port principal de Flask
EXPOSE 5000

# Démarrer l'application principale
CMD ["poetry", "run", "python", "main.py"]
