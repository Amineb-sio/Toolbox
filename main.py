from flask import Flask, render_template, redirect, url_for, session, request, jsonify, send_file
from flask_session import Session
import requests
import os
import tempfile
import json
import logging
from urllib.parse import urlencode
from functools import wraps
import psycopg2
import psycopg2.extras
import datetime
import csv

# Configurer le logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète'

# Configuration de Flask-Session pour stocker les sessions côté serveur
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = tempfile.mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = 1800
Session(app)

# Configuration Keycloak
KC_SERVER = "http://localhost:8080"
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

# Fonction de connexion à la base de données
def get_db_connection():
    """Établir une connexion à la base de données PostgreSQL."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        return conn
    except Exception as e:
        app.logger.error(f"Erreur de connexion à la base de données: {e}")
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
    
    response = requests.post(token_url, data=data)
    app.logger.debug(f"Réponse de token: {response.status_code}")
    
    if response.status_code == 200:
        return response.json()
    return None

def get_userinfo(access_token):
    """Obtenir les informations utilisateur avec le jeton d'accès"""
    userinfo_url = f"{KC_SERVER}/realms/{KC_REALM}/protocol/openid-connect/userinfo"
    headers = {'Authorization': f'Bearer {access_token}'}
    
    response = requests.get(userinfo_url, headers=headers)
    app.logger.debug(f"Réponse de userinfo: {response.status_code}")
    
    if response.status_code == 200:
        return response.json()
    return None

def is_logged_in():
    """Vérifier si l'utilisateur est connecté"""
    app.logger.debug(f"Session contient: {list(session.keys())}")
    return 'access_token' in session and 'roles' in session

def has_role(required_roles):
    """Vérifier si l'utilisateur a l'un des rôles requis"""
    if not is_logged_in():
        return False
    
    user_roles = session.get('roles', [])
    app.logger.debug(f"Rôles utilisateur: {user_roles}")
    app.logger.debug(f"Rôles requis: {required_roles}")
    return any(role in user_roles for role in required_roles)

def login_required(f):
    """Décorateur pour vérifier si l'utilisateur est connecté"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(required_roles):
    """Décorateur pour vérifier les rôles"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not is_logged_in():
                return redirect(url_for('login'))
            
            if not has_role(required_roles):
                return redirect(url_for('access_denied'))
            
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/')
def index():
    app.logger.debug(f"Index - Session contient: {list(session.keys())}")
    if is_logged_in():
        # Créer un dictionnaire user_info compatible avec vos templates
        user_info = {
            'preferred_username': session.get('preferred_username', ''),
            'email': session.get('email', ''),
            'sub': session.get('sub', ''),
            'realm_access': {'roles': session.get('roles', [])}
        }
        app.logger.debug(f"Utilisateur connecté: {user_info['preferred_username']}")
        app.logger.debug(f"Rôles: {user_info['realm_access']['roles']}")
        return render_template('index.html', user_info=user_info)
    
    app.logger.debug("Utilisateur non connecté")
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
    app.logger.debug(f"Redirection vers: {auth_url}")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Traiter le callback de Keycloak"""
    if 'code' not in request.args:
        app.logger.error("Pas de code reçu")
        return redirect(url_for('index'))
    
    code = request.args.get('code')
    app.logger.debug(f"Code reçu: {code[:10]}...")
    
    # Échanger le code contre un jeton
    token_data = get_token_from_code(code)
    if not token_data:
        app.logger.error("Impossible d'obtenir le jeton")
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
            app.logger.debug(f"Token décodé: {decoded}")
            if 'realm_access' in decoded and 'roles' in decoded['realm_access']:
                session['roles'] = decoded['realm_access']['roles']
            else:
                session['roles'] = []
        except ImportError:
            app.logger.warning("Module PyJWT non disponible, impossible de décoder le token")
            # Si PyJWT n'est pas installé, utilisez userinfo
            if 'realm_access' in userinfo and 'roles' in userinfo['realm_access']:
                session['roles'] = userinfo['realm_access']['roles']
            else:
                session['roles'] = []
        except Exception as e:
            app.logger.error(f"Erreur lors du décodage du jeton: {e}")
            # Si le décodage échoue, essayez d'obtenir les rôles depuis userinfo
            if 'realm_access' in userinfo and 'roles' in userinfo['realm_access']:
                session['roles'] = userinfo['realm_access']['roles']
            else:
                session['roles'] = []
        
        app.logger.debug(f"Session après connexion: {list(session.keys())}")
        app.logger.debug(f"Utilisateur: {session['preferred_username']}")
        app.logger.debug(f"Rôles: {session['roles']}")
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Déconnecter l'utilisateur"""
    # Supprimer les jetons de la session
    session.clear()
    
    # Se déconnecter de Keycloak (sans redirect_uri pour éviter l'erreur)
    logout_url = f"{KC_SERVER}/realms/{KC_REALM}/protocol/openid-connect/logout"
    
    # Rediriger vers Keycloak pour déconnecter la session Keycloak
    return redirect(logout_url)

@app.route('/access-denied')
def access_denied():
    return render_template('access_denied.html')

@app.route('/profile')
@login_required
def profile():
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

# -------------------- Nouvelles routes pour la gestion des rapports --------------------

@app.route('/reports')
@login_required
def reports():
    """Afficher la liste des rapports"""
    conn = get_db_connection()
    if not conn:
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
        
        return render_template('reports.html', 
                               reports=reports_list, 
                               user_info={'preferred_username': session.get('preferred_username', ''),
                                         'realm_access': {'roles': session.get('roles', [])}})
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des rapports: {e}")
        return f"Erreur: {e}", 500
    finally:
        conn.close()

@app.route('/reports/<module>')
@login_required
def module_reports(module):
    """Afficher les rapports d'un module spécifique"""
    # Vérifier si l'utilisateur a accès à ce module
    if module in tool_roles and not has_role(tool_roles[module]):
        return redirect(url_for('access_denied'))
    
    conn = get_db_connection()
    if not conn:
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
        
        return render_template('module_reports.html', 
                               reports=reports_list, 
                               module=module,
                               user_info={'preferred_username': session.get('preferred_username', ''),
                                         'realm_access': {'roles': session.get('roles', [])}})
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des rapports du module {module}: {e}")
        return f"Erreur: {e}", 500
    finally:
        conn.close()

@app.route('/report/<int:report_id>')
@login_required
def report_details(report_id):
    """Afficher les détails d'un rapport spécifique"""
    conn = get_db_connection()
    if not conn:
        return "Erreur de connexion à la base de données", 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer les informations de base du rapport
        cur.execute("SELECT * FROM rapports WHERE id = %s", (report_id,))
        report = cur.fetchone()
        
        if not report:
            cur.close()
            return "Rapport non trouvé", 404
        
        # Vérifier si l'utilisateur a accès à ce module
        module = report['module']
        if module in tool_roles and not has_role(tool_roles[module]):
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
            app.logger.warning(f"Le fichier n'existe pas: {report['chemin_fichier']}")
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
            except Exception as e:
                app.logger.error(f"Erreur lors de la lecture du CSV: {e}")
        
        # Ajout de la prévisualisation pour les fichiers TXT
        file_content = None
        if report['format'] == 'TXT' and file_exists:
            try:
                with open(report['chemin_fichier'], 'r', encoding='utf-8', errors='ignore') as file:
                    file_content = file.read(10000)  # Limiter à 10000 caractères
            except Exception as e:
                app.logger.error(f"Erreur lors de la lecture du fichier texte: {e}")
        
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
        app.logger.error(f"Erreur lors de la récupération des détails du rapport {report_id}: {e}")
        return f"Erreur: {e}", 500
    finally:
        conn.close()

@app.route('/download/<int:report_id>')
@login_required
def download_report(report_id):
    """Télécharger ou prévisualiser un rapport"""
    conn = get_db_connection()
    if not conn:
        return "Erreur de connexion à la base de données", 500
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer les informations du rapport
        cur.execute("SELECT * FROM rapports WHERE id = %s", (report_id,))
        report = cur.fetchone()
        
        if not report:
            cur.close()
            return "Rapport non trouvé", 404
        
        # Vérifier si l'utilisateur a accès à ce module
        module = report['module']
        if module in tool_roles and not has_role(tool_roles[module]):
            return redirect(url_for('access_denied'))
        
        cur.close()
        
        # Chemin du fichier
        file_path = report['chemin_fichier']
        
        # Vérifier si le fichier existe
        if not os.path.exists(file_path):
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
        
        # Renvoyer le fichier
        return send_file(file_path, 
                         mimetype=mime_type,
                         as_attachment=not preview,  # True pour téléchargement, False pour prévisualisation
                         download_name=file_name)
        
    except Exception as e:
        app.logger.error(f"Erreur lors du téléchargement du rapport {report_id}: {e}")
        return f"Erreur: {e}", 500
    finally:
        if conn:
            conn.close()

@app.route('/api/reports/stats')
@login_required
def report_stats():
    """API pour obtenir les statistiques des rapports"""
    conn = get_db_connection()
    if not conn:
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
        
        # Statistiques par format
        cur.execute("""
            SELECT format, COUNT(*) as count
            FROM rapports
            GROUP BY format
            ORDER BY count DESC
        """)
        format_stats = [dict(row) for row in cur.fetchall()]
        
        # Statistiques par date (derniers 30 jours)
        cur.execute("""
            SELECT DATE(date_creation) as date, COUNT(*) as count
            FROM rapports
            WHERE date_creation >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(date_creation)
            ORDER BY date
        """)
        date_stats = [dict(row) for row in cur.fetchall()]
        
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
        app.logger.error(f"Erreur lors de la récupération des statistiques: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/import-reports')
@login_required
@role_required(['admin'])  # Seuls les administrateurs peuvent importer des rapports
def import_reports_page():
    """Page pour lancer l'importation des rapports"""
    return render_template('import_reports.html',
                           user_info={'preferred_username': session.get('preferred_username', ''),
                                     'realm_access': {'roles': session.get('roles', [])}})

@app.route('/api/import-reports', methods=['POST'])
@login_required
@role_required(['admin'])
def import_reports():
    """API pour importer les rapports depuis les dossiers"""
    try:
        from import_reports import scan_directory
        
        # Récupérer le chemin du répertoire de la Toolbox depuis la requête ou utiliser le répertoire courant
        toolbox_dir = request.json.get('toolbox_dir')
        
        # Si aucun chemin n'est fourni, utiliser le répertoire courant où l'application est exécutée
        if not toolbox_dir:
            toolbox_dir = os.getcwd()
        
        app.logger.info(f"Lancement de l'importation depuis le répertoire: {toolbox_dir}")
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Erreur de connexion à la base de données"}), 500
        
        # Lancer l'importation
        result = scan_directory(conn, toolbox_dir)
        
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"Importation terminée avec succès. {result} rapports importés.",
            "directory_used": toolbox_dir
        })
    except Exception as e:
        app.logger.error(f"Erreur lors de l'importation des rapports: {e}")
        return jsonify({"error": str(e)}), 500

# Routes pour les différents outils avec vérification de rôle
@app.route('/nmap')
@login_required
@role_required(tool_roles['nmap'])
def nmap():
    return redirect(f"{base_url}:5001/")

@app.route('/webmin')
@login_required
@role_required(tool_roles['webmin'])
def webmin():
    return redirect(f"{base_url}:5002/")

@app.route('/wireshark')
@login_required
@role_required(tool_roles['wireshark'])
def wireshark():
    return redirect(f"{base_url}:5003/")

@app.route('/owasp')
@login_required
@role_required(tool_roles['owasp'])
def owasp():
    return redirect(f"{base_url}:5004/")

@app.route('/gobuster')
@login_required
@role_required(tool_roles['gobuster'])
def gobuster():
    return redirect(f"{base_url}:5005/")

@app.route('/wpscan')
@login_required
@role_required(tool_roles['wpscan'])
def wpscan():
    return redirect(f"{base_url}:5006/")

@app.route('/sqlmap')
@login_required
@role_required(tool_roles['sqlmap'])
def sqlmap():
    return redirect(f"{base_url}:5007/")

@app.route('/owaspdependencycheck')
@login_required
@role_required(tool_roles['owaspdependencycheck'])
def owaspdependencycheck():
    return redirect(f"{base_url}:5008/")

@app.route('/openvas')
@login_required
@role_required(tool_roles['openvas'])
def openvas():
    return redirect(f"{base_url}:5009/")

@app.route('/hydra')
@login_required
@role_required(tool_roles['hydra'])
def hydra():
    return redirect(f"{base_url}:5010/")

@app.route('/airodump-ng')
@login_required
@role_required(tool_roles['airodump-ng'])
def airodump():
    return redirect(f"{base_url}:5011/")

@app.route('/aircrack-ng')
@login_required
@role_required(tool_roles['aircrack-ng'])
def aircrack():
    return redirect(f"{base_url}:5012/")

@app.route('/nikto')
@login_required
@role_required(tool_roles['nikto'])
def nikto():
    return redirect(f"{base_url}:5013/")

@app.route('/sslyze')
@login_required
@role_required(tool_roles['sslyze'])
def sslyze():
    return redirect(f"{base_url}:5014/")

@app.route('/johntheripper')
@login_required
@role_required(tool_roles['johntheripper'])
def johntheripper():
    return redirect(f"{base_url}:5015/")

@app.route('/tcpdump')
@login_required
@role_required(tool_roles['tcpdump'])
def tcpdump():
    return redirect(f"{base_url}:5016/")

@app.route('/sherlock')
@login_required
@role_required(tool_roles['sherlock'])
def sherlock():
    return redirect(f"{base_url}:5017/")

@app.route('/harvester')
@login_required
@role_required(tool_roles['harvester'])
def harvester():
    return redirect(f"{base_url}:5018/")

@app.route('/metagoofil')
@login_required
@role_required(tool_roles['metagoofil'])
def metagoofil():
    return redirect(f"{base_url}:5019/")

@app.route('/subfinder')
@login_required
@role_required(tool_roles['subfinder'])
def subfinder():
    return redirect(f"{base_url}:5020/")

@app.route('/autosecurite')
@login_required
@role_required(tool_roles['autosecurite'])
def autosecurite():
    return redirect(f"{base_url}:5021/")

if __name__ == '__main__':
    # Créer le dossier de sessions s'il n'existe pas
    if not os.path.exists(app.config["SESSION_FILE_DIR"]):
        os.makedirs(app.config["SESSION_FILE_DIR"])
    
    # Afficher les configurations au démarrage
    app.logger.info(f"🚀 Application démarrée")
    app.logger.info(f"📁 Sessions stockées dans: {app.config['SESSION_FILE_DIR']}")
    app.logger.info(f"🔗 URL de base pour les redirections: {base_url}")
    app.logger.info(f"🔐 Keycloak configuré sur: {KC_SERVER}")
    
    # Lancement du serveur
    app.run(debug=True, host="0.0.0.0", port=5000)
