# Toolbox de Cybersécurité

<div align="center">
  
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.13+-green.svg)
![Licence](https://img.shields.io/badge/license-MIT-orange.svg)

</div>

Une suite complète d'outils de cybersécurité intégrés dans une interface web unifiée. Cette plateforme rassemble de nombreux outils populaires tels que Metasploit, Nmap, OWASP ZAP, et bien d'autres pour faciliter les tests de pénétration et les analyses de sécurité.

## 🌟 Fonctionnalités

- **Interface Unifiée** : Accédez à tous vos outils de sécurité depuis une seule interface web
- **Authentification Sécurisée** : Gestion des utilisateurs via Keycloak
- **Architecture Microservices** : Chaque outil est encapsulé dans son propre service
- **Sauvegarde et Restauration** : Système intégré de sauvegarde pour vos configurations et résultats
- **Système de Logs** : Journalisation complète des actions pour l'audit et le dépannage

## 🛠️ Outils Intégrés

- Metasploit Web Interface
- Nmap Scanner
- OWASP ZAP
- WPScan
- Gobuster
- TCPdump Analyzer
- SQLmap
- Hydra
- Nikto
- John the Ripper
- TheHarvester
- Subfinder
- Auto-Sécurité

## 📋 Prérequis

- Système d'exploitation Linux (Kali Linux recommandé)
- Python 3.13+
- Docker et Docker Compose
- Poetry (gestionnaire de dépendances Python)

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/Amineb-sio/Toolbox.git
cd Toolbox
```

### 2. Installation de Poetry (si non installé)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

### 3. Installation des dépendances

```bash
poetry install
```

### 4. Lancement des services Docker

```bash
docker-compose up -d
```

Cette commande démarrera :
- Portainer (port 9000)
- Keycloak (port 8080)
- PostgreSQL (port 5432)
- pgAdmin (port 5050)

### 5. Démarrage de la Toolbox

```bash
poetry run bash ./start_all.sh
```

L'application sera accessible à l'adresse : **http://127.0.0.1:5000**

## 🔐 Authentification

L'authentification est gérée par Keycloak, accessible sur **http://localhost:8080**. 

## 📁 Structure des Données

- **Sessions** : `/tmp/tmp[random]`
- **Sauvegardes** : `./backups`
- **Clés cryptographiques** : `./secure_keys`
- **Logs** : `./logs`

## 🐳 Gestion des Conteneurs Docker

### Arrêter et nettoyer tous les conteneurs et images

```bash
docker stop $(docker ps -aq) && docker rm $(docker ps -aq) && docker rmi $(docker images -q)
```

### Utilisation des modules Docker spécifiques

Pour les modules standard :
```bash
cd chemin/vers/module
docker-compose up -d
```

Pour les modules avec Dockerfile :
```bash
cd chemin/vers/module
docker-compose up --build -d
```

## 🔍 Dépannage

En cas de problème, vérifiez les journaux dans le répertoire `./logs`.

Pour redémarrer tous les services :
```bash
docker-compose down
docker-compose up -d
poetry run bash ./start_all.sh
```

## 📚 Documentation

Une documentation complète est disponible dans le dossier `docs/`.

## 🌐 Navigateurs Supportés

- Google Chrome (recommandé)
- Firefox
- Edge

## 👨‍💻 Développeurs

- Amine Boukherouba
- Stéphane YE
- Jeremy Corinthe

## 📜 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

⭐ N'hésitez pas à donner une étoile à ce projet si vous le trouvez utile !
