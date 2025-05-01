import logging
import logging.handlers
import os
import gzip
import time
import glob
from datetime import datetime

# Variable globale pour suivre si le logging a déjà été initialisé
_LOGGING_INITIALIZED = False

# Classe pour compresser automatiquement les logs tournés
class GzipRotator:
    def __call__(self, source, dest):
        with open(source, 'rb') as f_in:
            with gzip.open(f"{dest}.gz", 'wb') as f_out:
                f_out.writelines(f_in)
        os.remove(source)

# Classe de filtre pour réduire les logs inutiles
class LogFilter(logging.Filter):
    def filter(self, record):
        # Ignorer les requêtes pour les ressources statiques
        if isinstance(record.msg, str) and record.msg.startswith("HTTP GET /static/"):
            return False
        # Ignorer les heartbeats et autres requêtes non pertinentes
        if isinstance(record.msg, str) and "favicon.ico" in record.msg:
            return False
        return True

def compress_existing_logs():
    """Compresse tous les fichiers de logs existants non compressés"""
    log_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(log_dir):
        return
    
    # Recherche des fichiers de logs non compressés
    log_pattern = os.path.join(log_dir, 'toolbox_*.log')
    today_log = os.path.join(log_dir, f'toolbox_{datetime.now().strftime("%Y-%m-%d")}.log')
    
    for log_file in glob.glob(log_pattern):
        # Ne pas compresser le fichier log du jour
        if log_file == today_log:
            continue
            
        # Vérifier si ce fichier n'est pas déjà compressé
        if not log_file.endswith('.gz'):
            try:
                # Compresser le fichier
                with open(log_file, 'rb') as f_in:
                    with gzip.open(f"{log_file}.gz", 'wb') as f_out:
                        f_out.writelines(f_in)
                # Supprimer l'original après compression
                os.remove(log_file)
                print(f"Fichier log compressé: {log_file}")
            except Exception as e:
                print(f"Erreur lors de la compression de {log_file}: {e}")

def cleanup_old_logs(days=60):
    """Supprime les fichiers de logs plus anciens que le nombre de jours spécifié"""
    log_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(log_dir):
        return
        
    current_time = time.time()
    days_to_seconds = days * 24 * 60 * 60
    
    # Recherche des fichiers de logs (compressés ou non)
    log_pattern = os.path.join(log_dir, 'toolbox_*')
    
    for file_path in glob.glob(log_pattern):
        if os.path.isfile(file_path):
            # Vérifier l'âge du fichier
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > days_to_seconds:
                try:
                    os.remove(file_path)
                    print(f"Ancien fichier log supprimé: {file_path}")
                except Exception as e:
                    print(f"Erreur lors de la suppression de {file_path}: {e}")

def setup_logging(app, log_level=logging.INFO):
    """Configuration avancée du système de logging"""
    global _LOGGING_INITIALIZED
    
    # Si le logging a déjà été initialisé, retourner simplement le logger existant
    if _LOGGING_INITIALIZED:
        return logging.getLogger()
    
    # Marquer le logging comme initialisé
    _LOGGING_INITIALIZED = True
    
    # Compresser les logs existants et nettoyer les anciens
    compress_existing_logs()
    cleanup_old_logs()
    
    # Créer le répertoire de logs s'il n'existe pas
    log_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Nom du fichier de log basé sur la date
    log_filename = os.path.join(log_dir, f'toolbox_{datetime.now().strftime("%Y-%m-%d")}.log')
    
    # Configuration du handler pour la rotation des logs
    # Rotation quotidienne et conservation de 15 jours de logs (réduit de 30 à 15)
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_filename,
        when='midnight',
        interval=1,
        backupCount=15,  # Réduit la rétention à 15 jours au lieu de 30
        encoding='utf-8'
    )
    
    # Ajouter la compression automatique des fichiers de logs
    file_handler.rotator = GzipRotator()
    
    # Format des logs: timestamp court, niveau abrégé, module, message tronqué
    log_format = logging.Formatter(
        '%(asctime)s - %(levelname).1s - [%(module)s:%(lineno)d] - %(message).400s',  # Limite la longueur des messages
        datefmt='%m-%d %H:%M:%S'  # Format de date plus court
    )
    file_handler.setFormatter(log_format)
    
    # Ajouter le filtre pour éviter les logs inutiles
    log_filter = LogFilter()
    file_handler.addFilter(log_filter)
    
    # Configuration du handler de console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    console_handler.addFilter(log_filter)
    
    # Configuration du logger racine
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Supprimer les handlers existants
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Ajouter les nouveaux handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Configuration du logger Flask
    # Supprimer les handlers existants de app.logger
    for handler in app.logger.handlers[:]:
        app.logger.removeHandler(handler)
    
    # Désactiver la propagation pour éviter la duplication
    app.logger.propagate = False
    
    # Ajouter les handlers directement
    app.logger.handlers = [file_handler, console_handler]
    app.logger.setLevel(log_level)
    
    # Désactiver le logger werkzeug par défaut pour éviter la duplication
    werkzeug_logger = logging.getLogger('werkzeug')
    for handler in werkzeug_logger.handlers[:]:
        werkzeug_logger.removeHandler(handler)
    werkzeug_logger.propagate = False
    werkzeug_logger.setLevel(logging.ERROR)
    
    # Logger les informations de démarrage une seule fois
    app.logger.info("=" * 40)  # Réduit la longueur de la ligne de séparation
    app.logger.info(f"Démarrage Toolbox: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    app.logger.info(f"Log level: {logging.getLevelName(log_level)}")
    app.logger.info(f"Log file: {log_filename}")
    app.logger.info("=" * 40)
    
    return root_logger

def get_module_logger(module_name):
    """Créer un logger spécifique pour un module"""
    logger = logging.getLogger(module_name)
    return logger

class RequestLogger:
    """Middleware pour logger les requêtes HTTP"""
    
    def __init__(self, app, logger=None):
        self.app = app
        self.logger = logger or app.logger
    
    def __call__(self, environ, start_response):
        # Récupérer des informations sur la requête
        path = environ.get('PATH_INFO', '')
        method = environ.get('REQUEST_METHOD', '')
        remote_addr = environ.get('REMOTE_ADDR', '')
        user_agent = environ.get('HTTP_USER_AGENT', '')
        
        # Ne pas logger les requêtes pour les fichiers statiques
        if path.startswith('/static/'):
            return self.app(environ, start_response)
        
        # Créer une fonction de rappel modifiée pour capturer le code de statut
        def custom_start_response(status, headers, exc_info=None):
            # Logger la requête avec le code de statut (format plus concis)
            status_code = status.split(' ')[0]
            # Tronquer l'agent utilisateur pour économiser de l'espace
            ua_short = user_agent[:30] if user_agent else '-'
            self.logger.info(f"{method} {path} {status_code} {remote_addr} {ua_short}")
            return start_response(status, headers, exc_info)
        
        # Traiter la requête normalement
        return self.app(environ, custom_start_response)
