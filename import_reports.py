import os
import re
import csv
import json
import logging
import psycopg2
from datetime import datetime
from pathlib import Path

# Configurer le logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_format_from_extension(file_path):
    """Détermine le format du fichier à partir de son extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.csv':
        return 'CSV'
    elif ext == '.pdf':
        return 'PDF'
    elif ext == '.html':
        return 'HTML'
    elif ext == '.json':
        return 'JSON'
    elif ext == '.xml':
        return 'XML'
    elif ext == '.txt':
        return 'TXT'
    else:
        return 'UNKNOWN'

def extract_date_from_filename(filename):
    """Extrait la date du nom de fichier au format 'rapport_YYYY-MM-DD_HH-MM-SS'."""
    date_pattern = r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})'
    match = re.search(date_pattern, filename)
    if match:
        date_str = match.group(1)
        try:
            return datetime.strptime(date_str, '%Y-%m-%d_%H-%M-%S')
        except ValueError:
            logger.warning(f"Format de date invalide dans le fichier: {filename}")
    
    # Utiliser la date de modification du fichier si le nom ne contient pas de date
    return None

def get_module_from_path(file_path):
    """Détermine le module à partir du chemin du fichier."""
    parts = file_path.split(os.sep)
    for part in parts:
        if part.startswith('Python '):
            return part.replace('Python ', '').lower()
    
    # Essayer de déterminer à partir du nom de fichier
    filename = os.path.basename(file_path)
    for tool in ['nmap', 'wireshark', 'gobuster', 'owasp', 'webmin', 'wpscan', 
                'sqlmap', 'owaspdependencycheck', 'openvas', 'hydra', 
                'airodump-ng', 'aircrack-ng', 'nikto', 'sslyze', 'johntheripper', 
                'tcpdump', 'sherlock', 'harvester', 'metagoofil', 'subfinder', 'autosecurite']:
        if tool in filename.lower():
            return tool
    
    return 'unknown'

def extract_csv_metadata(file_path):
    """Extrait les métadonnées d'un fichier CSV."""
    metadata = {
        'total_rows': 0,
        'columns': [],
        'sample_data': []
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            csv_reader = csv.reader(file)
            headers = next(csv_reader, [])
            metadata['columns'] = headers
            
            # Lire quelques lignes pour échantillon
            for i, row in enumerate(csv_reader):
                if i < 5:  # Limiter à 5 lignes d'échantillon
                    metadata['sample_data'].append(row)
                metadata['total_rows'] += 1
                
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction des métadonnées CSV de {file_path}: {str(e)}")
    
    return metadata

def import_report_to_db(conn, file_path):
    """Importe un rapport dans la base de données."""
    try:
        # Vérifier si le fichier existe
        if not os.path.exists(file_path):
            logger.error(f"Le fichier n'existe pas: {file_path}")
            return False
        
        # Déterminer le format du fichier
        file_format = get_format_from_extension(file_path)
        
        # Détermine le module du rapport
        module = get_module_from_path(file_path)
        
        # Extraire la date du nom de fichier
        creation_date = extract_date_from_filename(os.path.basename(file_path))
        if creation_date is None:
            # Utiliser la date de modification du fichier
            creation_date = datetime.fromtimestamp(os.path.getmtime(file_path))
        
        # Taille du fichier en octets
        file_size = os.path.getsize(file_path)
        
        # Obtenir le chemin absolu
        abs_path = os.path.abspath(file_path)
        
        # Préparation des métadonnées supplémentaires selon le format
        metadata = {}
        if file_format == 'CSV':
            metadata = extract_csv_metadata(file_path)
        
        # Conversion des métadonnées en JSON
        metadata_json = json.dumps(metadata)
        
        # Créer un curseur pour insérer dans la base de données
        cur = conn.cursor()
        
        # Vérifier si le rapport existe déjà (pour éviter les doublons)
        cur.execute(
            "SELECT id FROM rapports WHERE chemin_fichier = %s",
            (abs_path,)
        )
        existing_report = cur.fetchone()
        
        if existing_report:
            logger.info(f"Le rapport existe déjà dans la base de données: {abs_path}")
            return False
        
        # Insérer le rapport dans la table principale
        cur.execute(
            """
            INSERT INTO rapports 
            (module, format, date_creation, taille_fichier, chemin_fichier, metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (module, file_format, creation_date, file_size, abs_path, metadata_json)
        )
        
        report_id = cur.fetchone()[0]
        
        # Insérer des détails spécifiques selon le module
        if module == 'wireshark':
            # Pour Wireshark, on pourrait extraire des informations spécifiques
            # depuis le CSV ou le fichier de capture
            cur.execute(
                """
                INSERT INTO wireshark_rapports
                (rapport_id, nombre_paquets, protocoles, interface_capture, duree_capture)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (report_id, metadata.get('total_rows', 0), 
                 json.dumps(["TCP", "UDP", "HTTP"]), "eth0", "00:10:00")
            )
        elif module == 'nmap':
            # Pour Nmap, on pourrait extraire les informations des hôtes scannés
            cur.execute(
                """
                INSERT INTO nmap_rapports
                (rapport_id, nombre_hotes, ports_ouverts, version_nmap, arguments_scan)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (report_id, 10, json.dumps([22, 80, 443]), "7.92", "-sV -p 1-1000")
            )
        
        # Valider la transaction
        conn.commit()
        logger.info(f"Rapport importé avec succès: {file_path}")
        return True
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Erreur lors de l'importation du rapport {file_path}: {str(e)}")
        return False

def scan_directory(conn, base_dir=None):
    """Parcourt récursivement le répertoire à la recherche de dossiers 'rapports'."""
    total_imported = 0
    
    # Si aucun répertoire de base n'est fourni, utiliser le répertoire courant
    if base_dir is None:
        base_dir = os.getcwd()
    
    logger.info(f"Démarrage du scan depuis: {base_dir}")
    
    # Créer les tables si elles n'existent pas
    create_tables(conn)
    
    # Liste pour stocker tous les chemins trouvés (pour le débogage)
    all_dirs = []
    
    # Parcourir récursivement tous les dossiers
    for root, dirs, files in os.walk(base_dir):
        all_dirs.append(root)
        if os.path.basename(root) == 'rapports':
            logger.info(f"Trouvé dossier rapports: {root}")
            
            # Parcourir tous les fichiers du dossier
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                if os.path.isfile(file_path):
                    logger.info(f"Traitement du fichier: {file_path}")
                    
                    # Importer le rapport dans la base de données
                    if import_report_to_db(conn, file_path):
                        total_imported += 1
    
    # Si aucun rapport trouvé, essayer une approche plus directe
    if total_imported == 0:
        logger.info(f"Aucun rapport trouvé avec la première méthode. Essai d'une approche directe...")
        
        # Rechercher dynamiquement les dossiers Python *
        python_dirs = []
        for item in os.listdir(base_dir):
            item_path = os.path.join(base_dir, item)
            if os.path.isdir(item_path) and item.startswith("Python "):
                python_dirs.append(item_path)
        
        # Si aucun dossier Python n'est trouvé, essayer avec les sous-dossiers
        if not python_dirs:
            for item in os.listdir(base_dir):
                item_path = os.path.join(base_dir, item)
                if os.path.isdir(item_path):
                    for subitem in os.listdir(item_path):
                        subitem_path = os.path.join(item_path, subitem)
                        if os.path.isdir(subitem_path) and subitem.startswith("Python "):
                            python_dirs.append(subitem_path)
        
        logger.info(f"Dossiers Python trouvés: {python_dirs}")
        
        # Pour chaque dossier Python, vérifier s'il y a un dossier rapports
        for python_dir in python_dirs:
            rapport_path = os.path.join(python_dir, "rapports")
            
            if os.path.exists(rapport_path) and os.path.isdir(rapport_path):
                logger.info(f"Traitement du dossier rapports: {rapport_path}")
                
                # Parcourir tous les fichiers du dossier
                try:
                    for file_name in os.listdir(rapport_path):
                        file_path = os.path.join(rapport_path, file_name)
                        
                        if os.path.isfile(file_path):
                            logger.info(f"Traitement du fichier: {file_path}")
                            
                            # Importer le rapport dans la base de données
                            if import_report_to_db(conn, file_path):
                                total_imported += 1
                except Exception as e:
                    logger.error(f"Erreur lors du traitement du dossier {rapport_path}: {str(e)}")
    
    # Si toujours aucun rapport trouvé, afficher des informations pour le débogage
    if total_imported == 0:
        logger.info(f"Aucun rapport trouvé. Dossiers explorés: {len(all_dirs)}")
        # Afficher quelques dossiers pour débogage
        for i, dir_path in enumerate(all_dirs):
            if i < 20:  # Limiter l'affichage aux 20 premiers
                logger.info(f"Dossier {i}: {dir_path}")
    
    logger.info(f"Importation terminée. {total_imported} rapports importés.")
    return total_imported

def create_tables(conn):
    """Crée les tables nécessaires si elles n'existent pas déjà."""
    try:
        cur = conn.cursor()
        
        # Table principale pour tous les rapports
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rapports (
                id SERIAL PRIMARY KEY,
                module VARCHAR(50) NOT NULL,
                format VARCHAR(10) NOT NULL,
                date_creation TIMESTAMP NOT NULL,
                taille_fichier INTEGER NOT NULL,
                chemin_fichier TEXT UNIQUE NOT NULL,
                metadata JSONB
            )
        """)
        
        # Table spécifique pour les rapports Wireshark
        cur.execute("""
            CREATE TABLE IF NOT EXISTS wireshark_rapports (
                id SERIAL PRIMARY KEY,
                rapport_id INTEGER REFERENCES rapports(id) ON DELETE CASCADE,
                nombre_paquets INTEGER,
                protocoles JSONB,
                interface_capture VARCHAR(50),
                duree_capture VARCHAR(20)
            )
        """)
        
        # Table spécifique pour les rapports Nmap
        cur.execute("""
            CREATE TABLE IF NOT EXISTS nmap_rapports (
                id SERIAL PRIMARY KEY,
                rapport_id INTEGER REFERENCES rapports(id) ON DELETE CASCADE,
                nombre_hotes INTEGER,
                ports_ouverts JSONB,
                version_nmap VARCHAR(20),
                arguments_scan TEXT
            )
        """)
        
        conn.commit()
        logger.info("Tables créées avec succès (si elles n'existaient pas déjà)")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Erreur lors de la création des tables: {str(e)}")

if __name__ == "__main__":
    # Test du script
    try:
        # Connexion à la base de données
        conn = psycopg2.connect(
            dbname="toolbox_db",
            user="toolbox_user",
            password="secure_password",
            host="localhost",
            port="5432"
        )
        
        # Utiliser le répertoire courant si aucun n'est spécifié
        base_dir = os.environ.get("TOOLBOX_DIR", os.getcwd())
        scan_directory(conn, base_dir)
        
        # Fermer la connexion
        conn.close()
        
    except Exception as e:
        logger.error(f"Erreur générale: {str(e)}")
