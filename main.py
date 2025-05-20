from flask import Flask, render_template, redirect, url_for, session, request, jsonify, send_file
from flask_session import Session
import requests
import os
import tempfile
import json
import datetime
import csv
import shutil
import tarfile
import uuid
import logging
from urllib.parse import urlencode
from functools import wraps
import psycopg2
import psycopg2.extras
import base64
from cryptography.fernet import Fernet

# Importer le système de logging
from logging_system import setup_logging, get_module_logger, RequestLogger

# Initialiser l'application Flask
app = Flask(__name__)
app.secret_key = 'votre_clé_secrète'
app.jinja_env.globals['datetime'] = datetime


# Ajouter le filtre datetime ici
@app.template_filter('datetime')
def format_datetime(value, format="%d/%m/%Y %H:%M"):
    """Formater une date en string"""
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

# Configuration de Flask-Session pour stocker les sessions côté serveur
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = tempfile.mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = 1800
Session(app)

# Configuration du système de logging
root_logger = setup_logging(app, logging.DEBUG if app.debug else logging.INFO)
logger = get_module_logger(__name__)  # Logger spécifique au module principal
app.wsgi_app = RequestLogger(app.wsgi_app, app.logger)  # Middleware pour logger les requêtes HTTP

# Configuration Keycloak - MISE À JOUR
KC_SERVER = "http://localhost:8080"  # Utiliser le nom complet du conteneur
KC_REALM = "Toolbox"
KC_CLIENT_ID = "python-app"
KC_CLIENT_SECRET = "lqGJ9GsF434c0gLGtFoRJOavP6YgSgPI"
KC_REDIRECT_URI = "http://127.0.0.1:5000/callback"


# Configuration de la base de données PostgreSQL
DB_CONFIG = {
    'dbname': 'toolbox_db',
    'user': 'toolbox_user',
    'password': 'secure_password',  # À modifier pour correspondre au docker-compose
    'host': 'localhost',
    'port': '5432'
}

# URL de base pour les redirections - utiliser une variable d'environnement ou configurable
base_url = os.environ.get("BASE_URL", "http://127.0.0.1")

# Chemin du répertoire de sauvegarde
BACKUP_DIR = os.path.join(os.getcwd(), 'backups')

# Chemin du répertoire des clés
KEYS_DIR = os.path.join(os.getcwd(), 'secure_keys')

# Assurez-vous que les répertoires existent
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)
    logger.info(f"Création du répertoire de clés: {KEYS_DIR}")

# Mappage entre les outils et les rôles requis
tool_roles = {
    'nmap': ['securite', 'admin'],
    'webmin': ['admin'],
    'wireshark': ['securite', 'admin'],
    'owasp': ['securite', 'admin'],
    'gobuster': ['developpement', 'admin'],
    'wpscan': ['developpement', 'admin'],
    'sqlmap': ['developpement', 'admin'],
    'owaspdependencycheck': ['developpement', 'admin'],
    'openvas': ['infrastructure', 'admin'],
    'hydra': ['infrastructure', 'admin'],
    'airodump-ng': ['infrastructure', 'admin'],
    'aircrack-ng': ['infrastructure', 'admin'],
    'nikto': ['support', 'admin'],
    'sslyze': ['support', 'admin'],
    'johntheripper': ['support', 'admin'],
    'tcpdump': ['support', 'admin'],
    'sherlock': ['osint', 'admin'],
    'harvester': ['osint', 'admin'],
    'metagoofil': ['osint', 'admin'],
    'subfinder': ['osint', 'admin'],
    'autosecurite': ['securite', 'admin']
}

# Classe de gestion des clés
class KeyManager:
    """Système de gestion des clés pour la toolbox"""
    
    def __init__(self, app_logger):
        self.logger = app_logger
        self.keys = {}
        self.master_key = None
        
        # Initialiser ou charger la clé maître
        self._initialize_master_key()
        
        # Charger les clés existantes
        self._load_keys()
    
    def _initialize_master_key(self):
        """Initialise ou charge la clé maître depuis le stockage sécurisé"""
        master_key_path = os.path.join(KEYS_DIR, 'master.key')
        
        if os.path.exists(master_key_path):
            # Charger la clé maître existante
            try:
                with open(master_key_path, 'rb') as key_file:
                    self.master_key = key_file.read()
                self.logger.info("Clé maître chargée avec succès")
            except Exception as e:
                self.logger.error(f"Erreur lors du chargement de la clé maître: {e}")
                # Générer une nouvelle clé en cas d'échec
                self._generate_master_key(master_key_path)
        else:
            # Générer une nouvelle clé maître
            self._generate_master_key(master_key_path)
    
    def _generate_master_key(self, key_path):
        """Génère une nouvelle clé maître et la sauvegarde"""
        try:
            # Générer une clé aléatoire
            self.master_key = Fernet.generate_key()
            
            # Sauvegarder la clé maître
            with open(key_path, 'wb') as key_file:
                key_file.write(self.master_key)
            
            # Définir des permissions restrictives sur le fichier
            os.chmod(key_path, 0o600)  # Lecture/écriture uniquement par le propriétaire
            
            self.logger.info("Nouvelle clé maître générée et sauvegardée")
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération de la clé maître: {e}")
    
    def _load_keys(self):
        """Charge toutes les clés existantes depuis le stockage"""
        keys_file = os.path.join(KEYS_DIR, 'keys.json')
        
        if os.path.exists(keys_file):
            try:
                with open(keys_file, 'rb') as f:
                    encrypted_data = f.read()
                
                # Déchiffrer les données avec la clé maître
                fernet = Fernet(self.master_key)
                decrypted_data = fernet.decrypt(encrypted_data)
                
                # Charger le dictionnaire de clés
                self.keys = json.loads(decrypted_data.decode('utf-8'))
                self.logger.info(f"Clés chargées: {len(self.keys)} clés trouvées")
            except Exception as e:
                self.logger.error(f"Erreur lors du chargement des clés: {e}")
                self.keys = {}
        else:
            self.logger.info("Aucun fichier de clés existant trouvé")
            self.keys = {}
    
    def _save_keys(self):
        """Sauvegarde toutes les clés dans le stockage sécurisé"""
        try:
            # Préparer les données à chiffrer
            data = json.dumps(self.keys).encode('utf-8')
            
            # Chiffrer les données avec la clé maître
            fernet = Fernet(self.master_key)
            encrypted_data = fernet.encrypt(data)
            
            # Sauvegarder les données chiffrées
            keys_file = os.path.join(KEYS_DIR, 'keys.json')
            with open(keys_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Définir des permissions restrictives sur le fichier
            os.chmod(keys_file, 0o600)  # Lecture/écriture uniquement par le propriétaire
            
            self.logger.info(f"Clés sauvegardées: {len(self.keys)} clés")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde des clés: {e}")
            return False
    
    def generate_key(self, key_name, description=None, expiry_days=365):
        """Génère une nouvelle clé avec un nom spécifique et une date d'expiration"""
        try:
            # Générer une nouvelle clé
            key = Fernet.generate_key()
            key_id = str(uuid.uuid4())
            
            # Créer l'entrée de clé avec métadonnées
            created_at = datetime.datetime.now().isoformat()
            expires_at = (datetime.datetime.now() + datetime.timedelta(days=expiry_days)).isoformat()
            
            self.keys[key_id] = {
                'name': key_name,
                'description': description,
                'key': base64.b64encode(key).decode('utf-8'),
                'created_at': created_at,
                'expires_at': expires_at,
                'revoked': False
            }
            
            # Sauvegarder les clés mises à jour
            if self._save_keys():
                self.logger.info(f"Nouvelle clé générée: {key_name} (ID: {key_id})")
                return key_id
            return None
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération de la clé {key_name}: {e}")
            return None
    
    def get_key(self, key_id):
        """Récupère une clé par son ID, si elle n'est pas expirée ou révoquée"""
        if key_id not in self.keys:
            self.logger.warning(f"Clé non trouvée: {key_id}")
            return None
        
        key_info = self.keys[key_id]
        
        # Vérifier si la clé est révoquée
        if key_info.get('revoked', False):
            self.logger.warning(f"Tentative d'utilisation d'une clé révoquée: {key_id}")
            return None
        
        # Vérifier si la clé a expiré
        now = datetime.datetime.now()
        expires_at = datetime.datetime.fromisoformat(key_info['expires_at'])
        
        if now > expires_at:
            self.logger.warning(f"Tentative d'utilisation d'une clé expirée: {key_id}")
            return None
        
        # Décodage de la clé
        try:
            key = base64.b64decode(key_info['key'])
            return key
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de la clé {key_id}: {e}")
            return None
    
    def revoke_key(self, key_id):
        """Révoque une clé, la rendant inutilisable"""
        if key_id not in self.keys:
            self.logger.warning(f"Tentative de révocation d'une clé inexistante: {key_id}")
            return False
        
        try:
            # Marquer la clé comme révoquée
            self.keys[key_id]['revoked'] = True
            self.keys[key_id]['revoked_at'] = datetime.datetime.now().isoformat()
            
            # Sauvegarder les modifications
            if self._save_keys():
                self.logger.info(f"Clé révoquée: {key_id}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Erreur lors de la révocation de la clé {key_id}: {e}")
            return False
    
    def rotate_key(self, key_id, expiry_days=365):
        """Fait pivoter une clé en générant une nouvelle version et révoquant l'ancienne"""
        if key_id not in self.keys:
            self.logger.warning(f"Tentative de rotation d'une clé inexistante: {key_id}")
            return None
        
        try:
            # Récupérer les informations de l'ancienne clé
            old_key_info = self.keys[key_id]
            key_name = old_key_info['name']
            description = old_key_info.get('description')
            
            # Générer une nouvelle clé avec les mêmes informations
            new_key_id = self.generate_key(key_name, description, expiry_days)
            
            if new_key_id:
                # Révoquer l'ancienne clé
                self.revoke_key(key_id)
                self.logger.info(f"Clé pivotée: {key_id} -> {new_key_id}")
                return new_key_id
            return None
        except Exception as e:
            self.logger.error(f"Erreur lors de la rotation de la clé {key_id}: {e}")
            return None
    
    def list_keys(self, include_revoked=False):
        """Liste toutes les clés actives (et optionnellement révoquées)"""
        result = []
        
        for key_id, key_info in self.keys.items():
            # Filtrer les clés révoquées si demandé
            if key_info.get('revoked', False) and not include_revoked:
                continue
            
            # Ajouter les informations de base (sans la clé elle-même)
            result.append({
                'id': key_id,
                'name': key_info['name'],
                'description': key_info.get('description'),
                'created_at': key_info['created_at'],
                'expires_at': key_info['expires_at'],
                'revoked': key_info.get('revoked', False),
                'revoked_at': key_info.get('revoked_at')
            })
        
        return result
    
    def encrypt_data(self, key_id, data):
        """Chiffre des données avec une clé spécifique"""
        key = self.get_key(key_id)
        if not key:
            return None
        
        try:
            # Si les données ne sont pas déjà en bytes, les encoder
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Chiffrer les données
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)
            
            return encrypted_data
        except Exception as e:
            self.logger.error(f"Erreur lors du chiffrement des données avec la clé {key_id}: {e}")
            return None
    
    def decrypt_data(self, key_id, encrypted_data):
        """Déchiffre des données avec une clé spécifique"""
        key = self.get_key(key_id)
        if not key:
            return None
        
        try:
            # Déchiffrer les données
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            return decrypted_data
        except Exception as e:
            self.logger.error(f"Erreur lors du déchiffrement des données avec la clé {key_id}: {e}")
            return None

# Initialiser le gestionnaire de clés
key_manager = KeyManager(logger)

# Fonction de connexion à la base de données
def get_db_connection():
    """Établir une connexion à la base de données PostgreSQL."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        logger.debug("Connexion à la base de données établie avec succès")
        return conn
    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données: {e}")
        return None

def get_token_from_code(code):
    """Échanger un code d'autorisation contre un jeton d'accès"""
    token_url = f"{KC_SERVER}/realms/{KC_REALM}/protocol/openid-connect/token"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': KC_REDIRECT_URI,
        'client_id': KC_CLIENT_ID,
        'client_secret': KC_CLIENT_SECRET
    }
    
    logger.debug(f"Demande de token à Keycloak: {token_url}")
    response = requests.post(token_url, data=data)
    logger.debug(f"Réponse de token: {response.status_code}")
    
    if response.status_code == 200:
        logger.info("Token obtenu avec succès")
        return response.json()
    
    logger.error(f"Échec d'obtention du token. Statut: {response.status_code}")
    return None

def get_userinfo(access_token):
    """Obtenir les informations utilisateur avec le jeton d'accès"""
    userinfo_url = f"{KC_SERVER}/realms/{KC_REALM}/protocol/openid-connect/userinfo"
    headers = {'Authorization': f'Bearer {access_token}'}
    
    logger.debug(f"Demande de userinfo à Keycloak: {userinfo_url}")
    logger.debug(f"Headers: {headers}")
    
    response = requests.get(userinfo_url, headers=headers)
    logger.debug(f"Réponse de userinfo: {response.status_code}")
    
    if response.status_code != 200:
        logger.error(f"Contenu de la réponse d'erreur: {response.text}")
    
    if response.status_code == 200:
        logger.info("Informations utilisateur obtenues avec succès")
        return response.json()
    
    logger.error(f"Échec d'obtention des informations utilisateur. Statut: {response.status_code}")
    return None

def is_logged_in():
    """Vérifier si l'utilisateur est connecté"""
    logged_in = 'access_token' in session and 'roles' in session
    logger.debug(f"Vérification de connexion utilisateur: {logged_in}")
    logger.debug(f"Session contient: {list(session.keys())}")
    return logged_in

def has_role(required_roles):
    """Vérifier si l'utilisateur a l'un des rôles requis"""
    if not is_logged_in():
        logger.debug("Vérification des rôles échouée: utilisateur non connecté")
        return False
    
    user_roles = session.get('roles', [])
    logger.debug(f"Rôles utilisateur: {user_roles}")
    logger.debug(f"Rôles requis: {required_roles}")
    
    has_required_role = any(role in user_roles for role in required_roles)
    logger.debug(f"L'utilisateur a les rôles requis: {has_required_role}")
    return has_required_role

def login_required(f):
    """Décorateur pour vérifier si l'utilisateur est connecté"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            logger.warning(f"Accès non autorisé à {f.__name__}: utilisateur non connecté")
            return redirect(url_for('login'))
        logger.debug(f"Accès autorisé à {f.__name__}: utilisateur connecté")
        return f(*args, **kwargs)
    return decorated

def role_required(required_roles):
    """Décorateur pour vérifier les rôles"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not is_logged_in():
                logger.warning(f"Accès non autorisé à {f.__name__}: utilisateur non connecté")
                return redirect(url_for('login'))
            
            if not has_role(required_roles):
                logger.warning(f"Accès non autorisé à {f.__name__}: rôles insuffisants")
                return redirect(url_for('access_denied'))
            
            logger.debug(f"Accès autorisé à {f.__name__}: utilisateur avec rôles adéquats")
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/')
def index():
    logger.debug(f"Requête à /index - Session contient: {list(session.keys())}")
    if is_logged_in():
        # Créer un dictionnaire user_info compatible avec vos templates
        user_info = {
            'preferred_username': session.get('preferred_username', ''),
            'email': session.get('email', ''),
            'sub': session.get('sub', ''),
            'realm_access': {'roles': session.get('roles', [])}
        }
        logger.info(f"Utilisateur connecté: {user_info['preferred_username']}")
        logger.debug(f"Rôles: {user_info['realm_access']['roles']}")
        return render_template('index.html', user_info=user_info)
    
    logger.debug("Utilisateur non connecté, redirection vers la page d'accueil")
    return render_template('landing.html')

@app.route('/login')
def login():
    """Rediriger vers Keycloak pour l'authentification"""
    auth_url = f"{KC_SERVER}/realms/{KC_REALM}/protocol/openid-connect/auth"
    params = {
        'client_id': KC_CLIENT_ID,
        'redirect_uri': KC_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile'
    }
    
    auth_url = f"{auth_url}?{urlencode(params)}"
    logger.debug(f"Redirection vers: {auth_url}")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Traiter le callback de Keycloak"""
    if 'code' not in request.args:
        logger.error("Pas de code reçu dans le callback")
        return redirect(url_for('index'))
    
    code = request.args.get('code')
    logger.debug(f"Code reçu: {code[:10]}...")
    
    # Échanger le code contre un jeton
    token_data = get_token_from_code(code)
    if not token_data:
        logger.error("Impossible d'obtenir le jeton")
        return redirect(url_for('index'))
    
    # Stocker uniquement les informations essentielles dans la session
    session['access_token'] = token_data['access_token']
    session['expires_at'] = token_data['expires_in']
    
    # Obtenir les informations utilisateur
    userinfo = get_userinfo(token_data['access_token'])
    if userinfo:
        # Stocker seulement les informations nécessaires
        session['preferred_username'] = userinfo.get('preferred_username', '')
        session['email'] = userinfo.get('email', '')
        session['sub'] = userinfo.get('sub', '')
        
        # Pour récupérer les rôles depuis le JWT
        try:
            # Essayer d'importer PyJWT
            import jwt
            # Essayer d'extraire les rôles directement du jeton d'accès
            decoded = jwt.decode(token_data['access_token'], options={"verify_signature": False})
            logger.debug(f"Token décodé: {decoded}")
            if 'realm_access' in decoded and 'roles' in decoded['realm_access']:
                session['roles'] = decoded['realm_access']['roles']
            else:
                session['roles'] = []
        except ImportError:
            logger.warning("Module PyJWT non disponible, impossible de décoder le token")
            # Si PyJWT n'est pas installé, utilisez userinfo
            if 'realm_access' in userinfo and 'roles' in userinfo['realm_access']:
                session['roles'] = userinfo['realm_access']['roles']
            else:
                session['roles'] = []
        except Exception as e:
            logger.error(f"Erreur lors du décodage du jeton: {e}")
            # Si le décodage échoue, essayez d'obtenir les rôles depuis userinfo
            if 'realm_access' in userinfo and 'roles' in userinfo['realm_access']:
                session['roles'] = userinfo['realm_access']['roles']
            else:
                session['roles'] = []
        
        logger.debug(f"Session après connexion: {list(session.keys())}")
        logger.info(f"Utilisateur connecté: {session['preferred_username']}")
        logger.debug(f"Rôles: {session['roles']}")
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Déconnecter l'utilisateur"""
    username = session.get('preferred_username', 'Utilisateur inconnu')
    # Supprimer les jetons de la session
    session.clear()
    
    # Se déconnecter de Keycloak (sans redirect_uri pour éviter l'erreur)
    logout_url = f"{KC_SERVER}/realms/{KC_REALM}/protocol/openid-connect/logout"
    
    logger.info(f"Déconnexion de l'utilisateur: {username}")
    # Rediriger vers Keycloak pour déconnecter la session Keycloak
    return redirect(logout_url)

@app.route('/access-denied')
def access_denied():
    logger.warning(f"Accès refusé pour l'utilisateur: {session.get('preferred_username', 'Inconnu')}")
    return render_template('access_denied.html')

@app.route('/profile')
@login_required
def profile():
    logger.debug(f"Accès au profil utilisateur: {session.get('preferred_username')}")
    user_info = {
        'preferred_username': session.get('preferred_username', ''),
        'email': session.get('email', ''),
        'sub': session.get('sub', ''),
        'realm_access': {'roles': session.get('roles', [])}
    }
    return render_template('profile.html', user_info=user_info)

# Route pour vérifier l'état de la session
@app.route('/check-session')
def check_session():
    if is_logged_in():
        return f"Connecté en tant que: {session.get('preferred_username')}, Rôles: {session.get('roles')}"
    else:
        return f"Session non authentifiée. Contenu: {list(session.keys())}"

# -------------------- Routes pour la gestion des clés --------------------

@app.route('/key-management')
@login_required
@role_required(['admin'])  # Seuls les administrateurs peuvent gérer les clés
def key_management_page():
    """Page pour la gestion des clés"""
    logger.debug("Accès à la page de gestion des clés")
    
    # Récupérer la liste des clés
    keys = key_manager.list_keys(include_revoked=True)
    
    # Date actuelle
    import datetime
    now = datetime.datetime.now()  # Date actuelle déjà calculée
    
    return render_template('key_management.html',
                           datetime=datetime,              # Module complet
                           datetime_class=datetime.datetime,  # La classe datetime
                           now=now,                        # Date actuelle
                           keys=keys,
                           user_info={'preferred_username': session.get('preferred_username', ''),
                                      'realm_access': {'roles': session.get('roles', [])}})

@app.route('/api/keys', methods=['GET'])
@login_required
@role_required(['admin'])
def list_keys_api():
    """API pour lister les clés"""
    include_revoked = request.args.get('include_revoked', 'false').lower() == 'true'
    keys = key_manager.list_keys(include_revoked=include_revoked)
    return jsonify({'keys': keys})

@app.route('/api/keys', methods=['POST'])
@login_required
@role_required(['admin'])
def create_key_api():
    """API pour créer une nouvelle clé"""
    data = request.json
    name = data.get('name')
    description = data.get('description')
    expiry_days = int(data.get('expiry_days', 365))
    
    if not name:
        return jsonify({'success': False, 'error': 'Nom de clé requis'}), 400
    
    key_id = key_manager.generate_key(name, description, expiry_days)
    
    if key_id:
        return jsonify({'success': True, 'key_id': key_id})
    else:
        return jsonify({'success': False, 'error': 'Erreur lors de la création de la clé'}), 500

@app.route('/api/keys/<key_id>/revoke', methods=['POST'])
@login_required
@role_required(['admin'])
def revoke_key_api(key_id):
    """API pour révoquer une clé"""
    success = key_manager.revoke_key(key_id)
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Erreur lors de la révocation de la clé'}), 500

@app.route('/api/keys/<key_id>/rotate', methods=['POST'])
@login_required
@role_required(['admin'])
def rotate_key_api(key_id):
    """API pour faire pivoter une clé"""
    data = request.json
    expiry_days = int(data.get('expiry_days', 365))
    
    new_key_id = key_manager.rotate_key(key_id, expiry_days)
    
    if new_key_id:
        return jsonify({'success': True, 'new_key_id': new_key_id})
    else:
        return jsonify({'success': False, 'error': 'Erreur lors de la rotation de la clé'}), 500

# -------------------- Routes pour la gestion des rapports --------------------
@app.route('/reports')
@login_required
def reports():
    """Afficher la liste des rapports"""
    logger.debug("Accès à la liste des rapports")
    conn = get_db_connection()
    if not conn:
        logger.error("Erreur de connexion à la base de données")
        return "Erreur de connexion à la base de données", 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT r.*, 
                   COUNT(*) OVER() as total_count
            FROM rapports r
            ORDER BY r.date_creation DESC
            LIMIT 100
        """)
        reports = cur.fetchall()
        
        # Convertir en liste de dictionnaires pour le template
        reports_list = []
        for report in reports:
            reports_list.append(dict(report))
        
        cur.close()
        logger.debug(f"Nombre de rapports récupérés: {len(reports_list)}")
        
        return render_template('reports.html', 
                               reports=reports_list, 
                               user_info={'preferred_username': session.get('preferred_username', ''),
                                         'realm_access': {'roles': session.get('roles', [])}})
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des rapports: {e}")
        return f"Erreur: {e}", 500
    finally:
        conn.close()

@app.route('/reports/<module>')
@login_required
def module_reports(module):
    """Afficher les rapports d'un module spécifique"""
    logger.debug(f"Accès aux rapports du module: {module}")
    # Vérifier si l'utilisateur a accès à ce module
    if module in tool_roles and not has_role(tool_roles[module]):
        logger.warning(f"Accès refusé aux rapports du module {module} pour {session.get('preferred_username')}")
        return redirect(url_for('access_denied'))
    
    conn = get_db_connection()
    if not conn:
        logger.error("Erreur de connexion à la base de données")
        return "Erreur de connexion à la base de données", 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT r.*, 
                   COUNT(*) OVER() as total_count
            FROM rapports r
            WHERE r.module = %s
            ORDER BY r.date_creation DESC
            LIMIT 100
        """, (module,))
        reports = cur.fetchall()
        
        # Convertir en liste de dictionnaires pour le template
        reports_list = []
        for report in reports:
            reports_list.append(dict(report))
        
        cur.close()
        logger.debug(f"Nombre de rapports récupérés pour le module {module}: {len(reports_list)}")
        
        return render_template('module_reports.html', 
                               reports=reports_list, 
                               module=module,
                               user_info={'preferred_username': session.get('preferred_username', ''),
                                         'realm_access': {'roles': session.get('roles', [])}})
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des rapports du module {module}: {e}")
        return f"Erreur: {e}", 500
    finally:
        conn.close()

@app.route('/report/<int:report_id>')
@login_required
def report_details(report_id):
    """Afficher les détails d'un rapport spécifique"""
    logger.debug(f"Accès aux détails du rapport ID: {report_id}")
    conn = get_db_connection()
    if not conn:
        logger.error("Erreur de connexion à la base de données")
        return "Erreur de connexion à la base de données", 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer les informations de base du rapport
        cur.execute("SELECT * FROM rapports WHERE id = %s", (report_id,))
        report = cur.fetchone()
        
        if not report:
            cur.close()
            logger.warning(f"Rapport non trouvé: {report_id}")
            return "Rapport non trouvé", 404
        
        # Vérifier si l'utilisateur a accès à ce module
        module = report['module']
        if module in tool_roles and not has_role(tool_roles[module]):
            logger.warning(f"Accès refusé au rapport {report_id} du module {module}")
            return redirect(url_for('access_denied'))
        
        # Récupérer les détails spécifiques selon le module
        details = None
        if module == 'wireshark':
            cur.execute("SELECT * FROM wireshark_rapports WHERE rapport_id = %s", (report_id,))
            details = cur.fetchone()
        elif module == 'nmap':
            cur.execute("SELECT * FROM nmap_rapports WHERE rapport_id = %s", (report_id,))
            details = cur.fetchone()
        # Ajouter d'autres modules selon vos besoins
        
        cur.close()
        
        # Vérifier si le chemin du fichier existe
        if not os.path.exists(report['chemin_fichier']):
            logger.warning(f"Le fichier n'existe pas: {report['chemin_fichier']}")
            file_exists = False
        else:
            file_exists = True
        
        # Ajout de la prévisualisation pour les fichiers CSV
        csv_data = None
        if report['format'] == 'CSV' and file_exists:
            try:
                with open(report['chemin_fichier'], 'r', encoding='utf-8', errors='ignore') as file:
                    csv_reader = csv.reader(file)
                    headers = next(csv_reader, [])
                    rows = []
                    total_rows = 0
                    for i, row in enumerate(csv_reader):
                        total_rows += 1
                        if i < 10:  # Limiter à 10 lignes pour la prévisualisation
                            rows.append(row)
                    
                    csv_data = {
                        'headers': headers,
                        'rows': rows,
                        'total_rows': total_rows + 1  # +1 pour inclure la ligne d'en-tête
                    }
                    logger.debug(f"Prévisualisation CSV générée pour le rapport {report_id}: {total_rows+1} lignes totales")
            except Exception as e:
                logger.error(f"Erreur lors de la lecture du CSV: {e}")
        
        # Ajout de la prévisualisation pour les fichiers TXT
        file_content = None
        if report['format'] == 'TXT' and file_exists:
            try:
                with open(report['chemin_fichier'], 'r', encoding='utf-8', errors='ignore') as file:
                    file_content = file.read(10000)  # Limiter à 10000 caractères
                    logger.debug(f"Prévisualisation TXT générée pour le rapport {report_id}")
            except Exception as e:
                logger.error(f"Erreur lors de la lecture du fichier texte: {e}")
        
        # Prévisualisation HTML non implémentée ici (nécessiterait plus d'efforts)
        
        return render_template('report_details.html', 
                               report=dict(report), 
                               details=dict(details) if details else None,
                               module=module,
                               csv_data=csv_data,
                               file_content=file_content,
                               file_exists=file_exists,
                               user_info={'preferred_username': session.get('preferred_username', ''),
                                         'realm_access': {'roles': session.get('roles', [])}})
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des détails du rapport {report_id}: {e}")
        return f"Erreur: {e}", 500
    finally:
        conn.close()

@app.route('/download/<int:report_id>')
@login_required
def download_report(report_id):
    """Télécharger ou prévisualiser un rapport"""
    logger.debug(f"Demande de téléchargement du rapport ID: {report_id}")
    conn = get_db_connection()
    if not conn:
        logger.error("Erreur de connexion à la base de données")
        return "Erreur de connexion à la base de données", 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer les informations du rapport
        cur.execute("SELECT * FROM rapports WHERE id = %s", (report_id,))
        report = cur.fetchone()
        
        if not report:
            cur.close()
            logger.warning(f"Rapport non trouvé: {report_id}")
            return "Rapport non trouvé", 404
        
        # Vérifier si l'utilisateur a accès à ce module
        module = report['module']
        if module in tool_roles and not has_role(tool_roles[module]):
            logger.warning(f"Accès refusé au téléchargement du rapport {report_id}")
            return redirect(url_for('access_denied'))
        
        cur.close()
        
        # Chemin du fichier
        file_path = report['chemin_fichier']
        
        # Vérifier si le fichier existe
        if not os.path.exists(file_path):
            logger.error(f"Le fichier n'existe pas: {file_path}")
            return "Le fichier n'existe pas", 404
        
        # Déterminer le type MIME en fonction du format
        mime_types = {
            'PDF': 'application/pdf',
            'CSV': 'text/csv',
            'HTML': 'text/html',
            'TXT': 'text/plain',
            'JSON': 'application/json',
            'XML': 'application/xml'
        }
        
        mime_type = mime_types.get(report['format'], 'application/octet-stream')
        
        # Nom du fichier pour le téléchargement
        file_name = os.path.basename(file_path)
        
        # Vérifier si c'est une prévisualisation ou un téléchargement
        preview = request.args.get('preview', 'false') == 'true'
        logger.info(f"{'Prévisualisation' if preview else 'Téléchargement'} du rapport {report_id}: {file_name}")
        
        # Renvoyer le fichier
        return send_file(file_path, 
                         mimetype=mime_type,
                         as_attachment=not preview,  # True pour téléchargement, False pour prévisualisation
                         download_name=file_name)
        
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement du rapport {report_id}: {e}")
        return f"Erreur: {e}", 500
    finally:
        if conn:
            conn.close()

@app.route('/api/reports/stats')
@login_required
def report_stats():
    """API pour obtenir les statistiques des rapports"""
    logger.debug("Demande de statistiques des rapports")
    conn = get_db_connection()
    if not conn:
        logger.error("Erreur de connexion à la base de données")
        return jsonify({"error": "Erreur de connexion à la base de données"}), 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Statistiques par module
        cur.execute("""
            SELECT module, COUNT(*) as count
            FROM rapports
            GROUP BY module
            ORDER BY count DESC
        """)
        modules_stats = [dict(row) for row in cur.fetchall()]
        logger.debug(f"Statistiques par module récupérées: {len(modules_stats)} modules")
        
        # Statistiques par format
        cur.execute("""
            SELECT format, COUNT(*) as count
            FROM rapports
            GROUP BY format
            ORDER BY count DESC
        """)
        format_stats = [dict(row) for row in cur.fetchall()]
        logger.debug(f"Statistiques par format récupérées: {len(format_stats)} formats")
        
        # Statistiques par date (derniers 30 jours)
        cur.execute("""
            SELECT DATE(date_creation) as date, COUNT(*) as count
            FROM rapports
            WHERE date_creation >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(date_creation)
            ORDER BY date
        """)
        date_stats = [dict(row) for row in cur.fetchall()]
        logger.debug(f"Statistiques par date récupérées: {len(date_stats)} jours")
        
        # Convertir les dates en chaînes de caractères
        for stat in date_stats:
            stat['date'] = stat['date'].strftime('%Y-%m-%d')
        
        cur.close()
        
        return jsonify({
            "modules": modules_stats,
            "formats": format_stats,
            "dates": date_stats
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/import-reports')
@login_required
@role_required(['admin'])  # Seuls les administrateurs peuvent importer des rapports
def import_reports_page():
    """Page pour lancer l'importation des rapports"""
    logger.debug("Accès à la page d'importation des rapports")
    return render_template('import_reports.html',
                           user_info={'preferred_username': session.get('preferred_username', ''),
                                     'realm_access': {'roles': session.get('roles', [])}})

@app.route('/api/import-reports', methods=['POST'])
@login_required
@role_required(['admin'])
def import_reports():
    """API pour importer les rapports depuis les dossiers"""
    logger.info("Lancement de l'importation des rapports")
    try:
        from import_reports import scan_directory
        
        # Récupérer le chemin du répertoire de la Toolbox depuis la requête ou utiliser le répertoire courant
        toolbox_dir = request.json.get('toolbox_dir')
        
        # Si aucun chemin n'est fourni, utiliser le répertoire courant où l'application est exécutée
        if not toolbox_dir:
            toolbox_dir = os.getcwd()
        
        logger.info(f"Lancement de l'importation depuis le répertoire: {toolbox_dir}")
        
        conn = get_db_connection()
        if not conn:
            logger.error("Erreur de connexion à la base de données")
            return jsonify({"error": "Erreur de connexion à la base de données"}), 500
        
        # Lancer l'importation
        result = scan_directory(conn, toolbox_dir)
        
        conn.close()
        
        logger.info(f"Importation terminée: {result} rapports importés")
        return jsonify({
            "success": True,
            "message": f"Importation terminée avec succès. {result} rapports importés.",
            "directory_used": toolbox_dir
        })
    except Exception as e:
        logger.error(f"Erreur lors de l'importation des rapports: {e}")
        return jsonify({"error": str(e)}), 500

# -------------------- Routes pour la sauvegarde et restauration --------------------

@app.route('/backup-restore')
@login_required
@role_required(['admin'])  # Seuls les administrateurs peuvent gérer les sauvegardes
def backup_restore_page():
    """Page pour la gestion des sauvegardes et restaurations"""
    logger.debug("Accès à la page de gestion des sauvegardes")
    # Récupérer la liste des sauvegardes disponibles
    backups = get_available_backups()
    
    return render_template('backup_restore.html',
                           backups=backups,
                           user_info={'preferred_username': session.get('preferred_username', ''),
                                     'realm_access': {'roles': session.get('roles', [])}})

def get_available_backups():
    """Récupère la liste des sauvegardes disponibles avec leurs métadonnées"""
    logger.debug(f"Recherche des sauvegardes dans {BACKUP_DIR}")
    backups = []
    
    if not os.path.exists(BACKUP_DIR):
        logger.warning(f"Le répertoire de sauvegarde n'existe pas: {BACKUP_DIR}")
        return backups
    
    for backup_file in os.listdir(BACKUP_DIR):
        if backup_file.endswith('.tar.gz') and backup_file.startswith('toolbox_backup_'):
            backup_path = os.path.join(BACKUP_DIR, backup_file)
            backup_id = backup_file.replace('toolbox_backup_', '').replace('.tar.gz', '')
            
            # Obtenir la taille du fichier en format lisible
            size_bytes = os.path.getsize(backup_path)
            size = format_size(size_bytes)
            
            # Obtenir la date à partir du nom du fichier ou de la date de modification
            try:
                date_str = backup_id.split('_')[0]
                date_obj = datetime.datetime.strptime(date_str, '%Y-%m-%d-%H-%M-%S')
                date = date_obj.strftime('%d %B %Y à %H:%M:%S')
            except:
                # Fallback à la date de modification du fichier
                mod_time = os.path.getmtime(backup_path)
                date = datetime.datetime.fromtimestamp(mod_time).strftime('%d %B %Y à %H:%M:%S')
            
            # Extraire le nombre de fichiers (si métadonnées disponibles)
            files_count = "Inconnu"
            try:
                # Tenter de lire le fichier metadata à l'intérieur de l'archive
                with tarfile.open(backup_path, 'r:gz') as tar:
                    for member in tar.getmembers():
                        if member.name.endswith('metadata.json'):
                            f = tar.extractfile(member)
                            if f:
                                metadata = json.loads(f.read().decode('utf-8'))
                                files_count = metadata.get('files_count', "Inconnu")
                                break
            except Exception as e:
                logger.error(f"Erreur lors de la lecture des métadonnées de {backup_file}: {e}")
                
            backups.append({
                'id': backup_id,
                'date': date,
                'size': size,
                'files_count': files_count,
                'path': backup_path
            })
            logger.debug(f"Sauvegarde trouvée: {backup_id} - {date} - {size} - {files_count} fichiers")
    
    # Trier par date (plus récente en premier)
    backups.sort(key=lambda x: x['id'], reverse=True)
    logger.info(f"Nombre total de sauvegardes trouvées: {len(backups)}")
    
    return backups

def format_size(size_bytes):
    """Formate une taille en octets en format lisible (KB, MB, GB)"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

@app.route('/api/create-backup', methods=['POST'])
@login_required
@role_required(['admin'])
def create_backup_api():
    """API pour créer une sauvegarde des rapports"""
    logger.info("Création d'une nouvelle sauvegarde")
    try:
        backup_id = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S') + '_' + str(uuid.uuid4())[:8]
        backup_path = os.path.join(BACKUP_DIR, f'toolbox_backup_{backup_id}.tar.gz')
        
        # Créer un répertoire temporaire pour la sauvegarde
        temp_dir = os.path.join(BACKUP_DIR, f'temp_{backup_id}')
        os.makedirs(temp_dir, exist_ok=True)
        logger.debug(f"Répertoire temporaire créé: {temp_dir}")
        
        # Récupérer les chemins des répertoires contenant des rapports
        tool_dirs = [d for d in os.listdir() if os.path.isdir(d) and d.startswith('Python')]
        logger.debug(f"Répertoires d'outils trouvés: {tool_dirs}")
        
        # Compteur de fichiers copiés
        files_count = 0
        
        # Copier les rapports de chaque outil dans le répertoire temporaire
        for tool_dir in tool_dirs:
            rapports_dir = os.path.join(tool_dir, 'rapports')
            if os.path.exists(rapports_dir) and os.path.isdir(rapports_dir):
                # Créer le même chemin dans le répertoire temporaire
                dest_dir = os.path.join(temp_dir, tool_dir, 'rapports')
                os.makedirs(dest_dir, exist_ok=True)
                logger.debug(f"Création du répertoire de destination: {dest_dir}")
                
                # Copier tous les fichiers
                for filename in os.listdir(rapports_dir):
                    src_file = os.path.join(rapports_dir, filename)
                    if os.path.isfile(src_file):
                        shutil.copy2(src_file, os.path.join(dest_dir, filename))
                        files_count += 1
                logger.debug(f"Fichiers copiés pour {tool_dir}: {files_count}")
        
        # Créer un fichier de métadonnées
        metadata = {
            'date': datetime.datetime.now().isoformat(),
            'created_by': session.get('preferred_username', 'unknown'),
            'files_count': files_count,
            'tools': tool_dirs
        }
        
        with open(os.path.join(temp_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.debug("Fichier de métadonnées créé")
        
        # Créer l'archive
        with tarfile.open(backup_path, 'w:gz') as tar:
            tar.add(temp_dir, arcname=os.path.basename(temp_dir))
        logger.info(f"Archive créée: {backup_path}")
        
        # Supprimer le répertoire temporaire
        shutil.rmtree(temp_dir)
        logger.debug(f"Répertoire temporaire supprimé: {temp_dir}")
        
        return jsonify({
            'success': True,
            'message': f'Sauvegarde créée avec succès. {files_count} fichiers sauvegardés.',
            'backup_id': backup_id
        })
    
    except Exception as e:
        logger.error(f"Erreur lors de la création de la sauvegarde: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/restore-backup', methods=['POST'])
@login_required
@role_required(['admin'])
def restore_backup_api():
    """API pour restaurer une sauvegarde"""
    try:
        data = request.json
        backup_id = data.get('backup_id')
        
        if not backup_id:
            logger.error("Identifiant de sauvegarde manquant")
            return jsonify({
                'success': False,
                'error': 'Identifiant de sauvegarde manquant'
            }), 400
        
        logger.info(f"Restauration de la sauvegarde: {backup_id}")
        backup_path = os.path.join(BACKUP_DIR, f'toolbox_backup_{backup_id}.tar.gz')
        
        if not os.path.exists(backup_path):
            logger.error(f"Sauvegarde introuvable: {backup_path}")
            return jsonify({
                'success': False,
                'error': 'Sauvegarde introuvable'
            }), 404
        
        # Créer un répertoire temporaire pour l'extraction
        temp_dir = os.path.join(BACKUP_DIR, f'restore_temp_{uuid.uuid4()}')
        os.makedirs(temp_dir, exist_ok=True)
        logger.debug(f"Répertoire temporaire créé pour la restauration: {temp_dir}")
        
        # Extraire l'archive
        with tarfile.open(backup_path, 'r:gz') as tar:
            tar.extractall(path=temp_dir)
        logger.debug(f"Archive extraite dans: {temp_dir}")
        
        # Trouver le sous-répertoire de base (généralement temp_[ID])
        base_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
        if not base_dirs:
            shutil.rmtree(temp_dir)
            logger.error("Structure de sauvegarde invalide")
            return jsonify({
                'success': False,
                'error': 'Structure de sauvegarde invalide'
            }), 400
        
        base_dir = os.path.join(temp_dir, base_dirs[0])
        logger.debug(f"Répertoire de base trouvé: {base_dir}")
        
        # Restaurer les fichiers dans les répertoires d'origine
        files_count = 0
        for item in os.listdir(base_dir):
            item_path = os.path.join(base_dir, item)
            
            # Ignorer les fichiers de métadonnées
            if item == 'metadata.json':
                continue
            
            # Vérifier s'il s'agit d'un répertoire d'outil
            if os.path.isdir(item_path) and item.startswith('Python'):
                rapports_src = os.path.join(item_path, 'rapports')
                
                if os.path.exists(rapports_src) and os.path.isdir(rapports_src):
                    # Chemin de destination dans la toolbox
                    rapports_dest = os.path.join(os.getcwd(), item, 'rapports')
                    
                    # Créer le répertoire de destination s'il n'existe pas
                    os.makedirs(rapports_dest, exist_ok=True)
                    logger.debug(f"Restauration dans: {rapports_dest}")
                    
                    # Copier tous les fichiers
                    for filename in os.listdir(rapports_src):
                        src_file = os.path.join(rapports_src, filename)
                        if os.path.isfile(src_file):
                            shutil.copy2(src_file, os.path.join(rapports_dest, filename))
                            files_count += 1
        
        # Nettoyer
        shutil.rmtree(temp_dir)
        logger.debug(f"Répertoire temporaire supprimé: {temp_dir}")
        logger.info(f"Restauration terminée: {files_count} fichiers restaurés")
        
        return jsonify({
            'success': True,
            'message': f'{files_count} fichiers restaurés avec succès',
            'files_count': files_count
        })
    
    except Exception as e:
        logger.error(f"Erreur lors de la restauration de la sauvegarde: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/delete-backup', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_backup_api():
    """API pour supprimer une sauvegarde"""
    try:
        data = request.json
        backup_id = data.get('backup_id')
        
        if not backup_id:
            logger.error("Identifiant de sauvegarde manquant")
            return jsonify({
                'success': False,
                'error': 'Identifiant de sauvegarde manquant'
            }), 400
        
        logger.info(f"Suppression de la sauvegarde: {backup_id}")
        backup_path = os.path.join(BACKUP_DIR, f'toolbox_backup_{backup_id}.tar.gz')
        
        if not os.path.exists(backup_path):
            logger.error(f"Sauvegarde introuvable: {backup_path}")
            return jsonify({
                'success': False,
                'error': 'Sauvegarde introuvable'
            }), 404
        
        # Supprimer le fichier de sauvegarde
        os.remove(backup_path)
        logger.info(f"Sauvegarde supprimée: {backup_path}")
        
        return jsonify({
            'success': True,
            'message': 'Sauvegarde supprimée avec succès'
        })
    
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de la sauvegarde: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
# Routes pour les différents outils avec vérification de rôle
@app.route('/nmap')
@login_required
@role_required(tool_roles['nmap'])
def nmap():
    logger.info(f"Redirection vers nmap: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5001/")

@app.route('/webmin')
@login_required
@role_required(tool_roles['webmin'])
def webmin():
    logger.info(f"Redirection vers webmin: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5002/")

@app.route('/wireshark')
@login_required
@role_required(tool_roles['wireshark'])
def wireshark():
    logger.info(f"Redirection vers wireshark: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5003/")

@app.route('/owasp')
@login_required
@role_required(tool_roles['owasp'])
def owasp():
    logger.info(f"Redirection vers owasp: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5004/")

@app.route('/gobuster')
@login_required
@role_required(tool_roles['gobuster'])
def gobuster():
    logger.info(f"Redirection vers gobuster: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5005/")

@app.route('/wpscan')
@login_required
@role_required(tool_roles['wpscan'])
def wpscan():
    logger.info(f"Redirection vers wpscan: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5006/")

@app.route('/sqlmap')
@login_required
@role_required(tool_roles['sqlmap'])
def sqlmap():
    logger.info(f"Redirection vers sqlmap: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5007/")

@app.route('/owaspdependencycheck')
@login_required
@role_required(tool_roles['owaspdependencycheck'])
def owaspdependencycheck():
    logger.info(f"Redirection vers owaspdependencycheck: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5008/")

@app.route('/openvas')
@login_required
@role_required(tool_roles['openvas'])
def openvas():
    logger.info(f"Redirection vers openvas: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5009/")

@app.route('/hydra')
@login_required
@role_required(tool_roles['hydra'])
def hydra():
    logger.info(f"Redirection vers hydra: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5010/")

@app.route('/airodump-ng')
@login_required
@role_required(tool_roles['airodump-ng'])
def airodump():
    logger.info(f"Redirection vers airodump-ng: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5011/")

@app.route('/aircrack-ng')
@login_required
@role_required(tool_roles['aircrack-ng'])
def aircrack():
    logger.info(f"Redirection vers aircrack-ng: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5012/")

@app.route('/nikto')
@login_required
@role_required(tool_roles['nikto'])
def nikto():
    logger.info(f"Redirection vers nikto: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5013/")

@app.route('/sslyze')
@login_required
@role_required(tool_roles['sslyze'])
def sslyze():
    logger.info(f"Redirection vers sslyze: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5014/")

@app.route('/johntheripper')
@login_required
@role_required(tool_roles['johntheripper'])
def johntheripper():
    logger.info(f"Redirection vers johntheripper: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5015/")

@app.route('/tcpdump')
@login_required
@role_required(tool_roles['tcpdump'])
def tcpdump():
    logger.info(f"Redirection vers tcpdump: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5016/")

@app.route('/sherlock')
@login_required
@role_required(tool_roles['sherlock'])
def sherlock():
    logger.info(f"Redirection vers sherlock: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5017/")

@app.route('/harvester')
@login_required
@role_required(tool_roles['harvester'])
def harvester():
    logger.info(f"Redirection vers harvester: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5018/")

@app.route('/metagoofil')
@login_required
@role_required(tool_roles['metagoofil'])
def metagoofil():
    logger.info(f"Redirection vers metagoofil: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5019/")

@app.route('/subfinder')
@login_required
@role_required(tool_roles['subfinder'])
def subfinder():
    logger.info(f"Redirection vers subfinder: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5020/")

@app.route('/autosecurite')
@login_required
@role_required(tool_roles['autosecurite'])
def autosecurite():
    logger.info(f"Redirection vers autosecurite: {session.get('preferred_username')}")
    return redirect(f"{base_url}:5021/")

if __name__ == '__main__':
    # Créer le dossier de sessions s'il n'existe pas
    if not os.path.exists(app.config["SESSION_FILE_DIR"]):
        os.makedirs(app.config["SESSION_FILE_DIR"])
    
    # Créer le dossier de sauvegardes s'il n'existe pas
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        
    # Créer le dossier de logs s'il n'existe pas
    log_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    # Créer le dossier des clés s'il n'existe pas
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    
    # Afficher les configurations au démarrage
    logger.info(f"🚀 Application démarrée")
    logger.info(f"📁 Sessions stockées dans: {app.config['SESSION_FILE_DIR']}")
    logger.info(f"💾 Sauvegardes stockées dans: {BACKUP_DIR}")
    logger.info(f"🔑 Clés cryptographiques stockées dans: {KEYS_DIR}")
    logger.info(f"📊 Logs stockés dans: {log_dir}")
    logger.info(f"🔗 URL de base pour les redirections: {base_url}")
    logger.info(f"🔐 Keycloak configuré sur: {KC_SERVER}")
    
    # Ajouter un message avec des liens cliquables
    logger.info(f"🌐 Accéder à l'application via: http://127.0.0.1:5000 ou http://localhost:5000")
    
    # Lancement du serveur sans rechargement automatique
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
