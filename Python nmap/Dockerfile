# Utiliser l'image Kali Linux
FROM kalilinux/kali-rolling

# Définir le répertoire de travail
WORKDIR /app

# Copier tous les fichiers de l'application
COPY . .

# Installer les dépendances système
RUN apt update && apt install -y \
    nmap python3 python3-pip python3-venv sudo && \
    rm -rf /var/lib/apt/lists/*

# Créer un environnement virtuel et installer les dépendances dedans
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir flask python-nmap

# Donner les permissions pour utiliser Nmap sans mot de passe
RUN echo "kali ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers

# Exposer le port 5001
EXPOSE 5001

# Définir la commande pour lancer Flask avec l'environnement virtuel
CMD ["/app/venv/bin/python", "app.py"]

