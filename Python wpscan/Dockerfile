# Utiliser une image de base officielle avec Python et Kali
FROM kalilinux/kali-rolling

# Définir le répertoire de travail
WORKDIR /app

# Copier tous les fichiers de l'application
COPY . .

# Installer les dépendances nécessaires
RUN apt update && apt install -y \
    ruby ruby-dev libffi-dev build-essential \
    python3 python3-pip python3-venv sudo wpscan && \
    rm -rf /var/lib/apt/lists/*

# Créer un environnement virtuel et y installer Flask
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir flask

# Exposer le port utilisé par Flask
EXPOSE 5006

# Définir la commande pour lancer Flask avec l'environnement virtuel
CMD ["/app/venv/bin/python", "app.py"]
