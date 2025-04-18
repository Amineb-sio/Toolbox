# Toolbox - Guide d'installation et d'utilisation

Ce document détaille les étapes nécessaires pour installer et utiliser la toolbox.

## Prérequis

- Python 3
- Docker et Docker Compose (pour certains modules)
- Un système Linux (recommandé Kali Linux)

## Installation de Poetry

Poetry est utilisé pour gérer les dépendances du projet.

```bash
# Installation de Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Vérification de l'installation
poetry --version
```

## Installation des dépendances du projet

```bash
# Installation des dépendances
poetry install

# Vérification des dépendances installées (marquées en bleu)
poetry show
```

## Configuration

Avant de lancer la toolbox, vous devez configurer votre adresse IP dans le fichier `main.py`.

```bash
# Récupération de votre adresse IP
ip a

# Remplacez l'URL dans main.py par votre adresse IP
# Exemple: "http://192.168.1.10"
```

## Lancement de la toolbox

```bash
poetry run bash ./start_all.sh
```

## Installation de Docker (pour les modules complémentaires)

Si vous utilisez Kali Linux et que vous souhaitez tester les conteneurs avec certains outils :

```bash
# Installation de Docker
sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo usermod -aG docker $USER

# Installation de Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Vérification de l'installation
docker-compose --version
```

## Utilisation des modules Docker

Pour les modules standard :

```bash
# Se placer dans le dossier du module
cd chemin/vers/module

# Lancer le conteneur
docker-compose up -d
```

Pour les modules avec Dockerfile :

```bash
# Se placer dans le dossier du module
cd chemin/vers/module

# Construire et lancer le conteneur
docker-compose up --build -d
```

## Configuration du clavier français sur Kali Linux

```bash
# Méthode rapide
setxkbmap fr

# Méthode permanente
sudo dpkg-reconfigure keyboard-configuration
# Choisir le premier PC
# Choisir French AZERTY
# Valider les options suivantes avec Entrée
```

## Tâches à réaliser

- Architecture
  - [ ] Concevoir l'architecture globale de la toolbox (Amine)
  - [ ] Définir les interfaces entre les différents modules (Amine, Jeremy, Stephane)
  - [ ] Concevoir le système de stockage des résultats (Amine)
- Développement
  - [x] Développer l'interface utilisateur (Amine)
  - [ ] Créer le module de gestion des plugins (Amine)
  - [ ] Implémenter le système de logging (Amine)
- Intégration
  - [x] Intégrer Metasploit pour l'exploitation (Amine)
  - [x] Intégrer Wireshark pour l'analyse de trafic (Amine)
  - [x] Intégrer SQLmap pour la détection et l'exploitation des injections SQL (Amine)
- Sécurité
  - [ ] Configurer l'authentification et l'autorisation des utilisateurs (Amine)
  - [ ] Mettre en place un système de gestion des clés (Amine)
  - [x] Ajouter une vérification de mot de passe renforcée (ex: contraintes de complexité et expiration) (Amine)
- Tests
  - [ ] Créer des scénarios de tests d'intégration (Amine)
- Documentation
  - [ ] Rédiger la documentation technique de la toolbox (Jeremy, Amine, Stephane)
  - [ ] Élaborer un guide de dépannage (Amine)
- Déploiement
  - [ ] Configurer l'environnement de production (Amine)
  - [ ] Créer des scripts de déploiement automatisé (Amine)
  - [ ] Mettre en place un système de sauvegarde et restauration (Amine)
- Forensique
  - [ ] Intégrer des capacités d'analyse de trafic réseau (Amine)
- Optimisation
  - [ ] Réduire la taille des fichiers journaux (Amine)