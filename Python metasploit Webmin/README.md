# Webmin Exploitation Tool

Cette application Flask permet de gérer un conteneur Docker Webmin et d'automatiser son exploitation via Metasploit.

## Prérequis

Avant de commencer, assurez-vous que les éléments suivants sont installés sur votre système :

- **Python 3.8 ou supérieur**
- **Docker** (installé et en cours d'exécution)
- **pip** (le gestionnaire de paquets Python)

## Installation

Suivez ces étapes pour configurer l'application :

1. **Clonez ce dépôt :**

   ```bash
   git clone https://github.com/Amineb-sio/Toolbox.git -b Amine
   cd Toolbox
   ```

2. **Créez et activez un environnement virtuel :**

   - Sous Linux/Mac :
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - Sous Windows :
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```

3. **Installez les dépendances nécessaires :**

   ```bash
   pip install -r requirements.txt
   ```

4. **Vérifiez que Docker est en cours d'exécution :**

   - Sous Linux :
     ```bash
     sudo systemctl start docker
     ```
   - Sous Windows/Mac : Assurez-vous que Docker Desktop est démarré.

## Lancement de l'application

1. **Activez l'environnement virtuel si ce n'est pas déjà fait :**

   - Sous Linux/Mac :
     ```bash
     source venv/bin/activate
     ```
   - Sous Windows :
     ```bash
     venv\Scripts\activate
     ```

2. **Lancez l'application Flask :**

   ```bash
   python app.py
   ```

3. **Accédez à l'application via votre navigateur :**

   ```
   http://localhost:5000
   ```

## Fonctionnalités

- **Démarrer le conteneur Webmin** :\
  Permet de lancer un conteneur Docker exécutant Webmin sur le port 10000.

- **Arrêter le conteneur Webmin** :\
  Permet d'arrêter un conteneur Docker en cours d'exécution.

- **Exploitation Webmin** :\
  Automatisation de l'exploitation via Metasploit. Vous pouvez définir les adresses IP (LHOST et RHOST) directement via l'interface web.

## Structure du projet

- **`app.py`** : Script principal de l'application Flask.
- **`templates/index.html`** : Interface utilisateur HTML.
- **`requirements.txt`** : Liste des dépendances Python nécessaires.

## Dépannage

### Problèmes courants

- **Port déjà utilisé :**\
  Si le port 10000 est occupé, arrêtez le service ou conteneur qui utilise ce port avant de démarrer l'application.

  ```bash
  sudo netstat -tuln | grep 10000  # Trouver le processus utilisant le port
  sudo kill -9 <PID>               # Arrêter le processus
  ```

- **Erreur ********`ModuleNotFoundError`********:**\
  Si un module manque, assurez-vous que l'environnement virtuel est activé et que les dépendances sont installées :

  ```bash
  source venv/bin/activate  # Linux/Mac
  venv\Scripts\activate     # Windows
  pip install -r requirements.txt
  ```

---




