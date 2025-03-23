from flask import Flask, render_template, request, jsonify, send_file
import requests
import json
import os
import time
import socket
import urllib.parse
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='zap_web.log')
logger = logging.getLogger('zap_web')

app = Flask(__name__)
ZAP_API_URL = "http://127.0.0.1:8080"
API_KEY = "monapikey"  # Remplacez par votre clé API ZAP

# Timeout pour les requêtes vers ZAP
ZAP_TIMEOUT = 10  # secondes

@app.route('/')
def index():
    return render_template('index.html')

def is_zap_running():
    """Vérifie si ZAP est en cours d'exécution sur le port 8080"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Timeout réduit pour une vérification rapide
            return s.connect_ex(('127.0.0.1', 8080)) == 0
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de ZAP: {str(e)}")
        return False

@app.route('/check_zap', methods=['GET'])
def check_zap():
    """Vérifie si ZAP est accessible et fonctionnel"""
    logger.info("Vérification de la connexion à ZAP")
    
    if not is_zap_running():
        logger.warning("ZAP n'est pas en cours d'exécution sur le port 8080")
        return jsonify({"status": "error", "message": "ZAP n'est pas en cours d'exécution sur le port 8080"})
    
    try:
        response = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/?apikey={API_KEY}", timeout=ZAP_TIMEOUT)
        if response.status_code == 200:
            version = response.json().get('version', 'inconnue')
            logger.info(f"ZAP est accessible (version {version})")
            return jsonify({"status": "ok", "message": f"ZAP est accessible (version {version})"})
        else:
            logger.warning(f"ZAP a répondu avec le code {response.status_code}")
            return jsonify({"status": "error", "message": f"ZAP a répondu avec le code {response.status_code}"})
    except requests.exceptions.ConnectionError:
        logger.error("Impossible de se connecter à ZAP")
        return jsonify({"status": "error", "message": "Impossible de se connecter à ZAP"})
    except requests.exceptions.Timeout:
        logger.error("Délai d'attente dépassé lors de la connexion à ZAP")
        return jsonify({"status": "error", "message": "Délai d'attente dépassé lors de la connexion à ZAP"})
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de ZAP: {str(e)}")
        return jsonify({"status": "error", "message": f"Erreur: {str(e)}"})

def add_to_zap_scope(target_url):
    """Ajoute une URL au scope de ZAP en utilisant plusieurs méthodes"""
    try:
        # S'assurer que l'URL est formatée correctement
        if not target_url.startswith("http"):
            target_url = "http://" + target_url
            
        logger.info(f"Ajout de l'URL au scope: {target_url}")
            
        # Encoder l'URL pour l'API
        encoded_url = urllib.parse.quote(target_url)
        
        # Méthode 1: API standard
        scope_response = requests.get(f"{ZAP_API_URL}/JSON/core/action/includeInScope/?apikey={API_KEY}&url={encoded_url}", timeout=ZAP_TIMEOUT)
        scope_success = scope_response.status_code == 200 and "OK" in scope_response.text
        
        if scope_success:
            logger.info("URL ajoutée au scope avec succès (méthode 1)")
        else:
            logger.warning("Échec de l'ajout de l'URL au scope (méthode 1)")
        
        # Méthode 2: Essayer de créer et utiliser un contexte
        context_name = "ZAPWebContext"
        
        # Vérifier si le contexte existe déjà
        contexts_response = requests.get(f"{ZAP_API_URL}/JSON/context/view/contextList/?apikey={API_KEY}", timeout=ZAP_TIMEOUT)
        contexts = contexts_response.json().get("contextList", [])
        
        context_exists = False
        for context in contexts:
            if context_name in str(context):
                context_exists = True
                logger.info(f"Le contexte '{context_name}' existe déjà")
                break
                
        # Créer le contexte s'il n'existe pas
        if not context_exists:
            logger.info(f"Création du contexte '{context_name}'")
            new_context_response = requests.get(
                f"{ZAP_API_URL}/JSON/context/action/newContext/?apikey={API_KEY}&contextName={context_name}",
                timeout=ZAP_TIMEOUT
            )
            context_exists = new_context_response.status_code == 200
            
        # Ajouter l'URL au contexte
        if context_exists:
            # Ajouter l'URL et toutes ses sous-pages au contexte
            regex = f"{target_url}.*"
            encoded_regex = urllib.parse.quote(regex)
            logger.info(f"Ajout de l'URL au contexte: {regex}")
            include_in_context = requests.get(
                f"{ZAP_API_URL}/JSON/context/action/includeInContext/?apikey={API_KEY}&contextName={context_name}&regex={encoded_regex}",
                timeout=ZAP_TIMEOUT
            )
            context_success = include_in_context.status_code == 200
            
            if context_success:
                logger.info("URL ajoutée au contexte avec succès (méthode 2)")
            else:
                logger.warning("Échec de l'ajout de l'URL au contexte (méthode 2)")
        else:
            context_success = False
            logger.warning(f"Impossible de créer le contexte '{context_name}'")
            
        # Méthode 3: Définir comme contexte par défaut si les méthodes précédentes ont échoué
        if not scope_success and not context_success:
            logger.info("Tentative d'utilisation du contexte par défaut")
            default_context = requests.get(
                f"{ZAP_API_URL}/JSON/context/action/setContextInScope/?apikey={API_KEY}&contextName=Default+Context&booleanInScope=true",
                timeout=ZAP_TIMEOUT
            )
            
            # Configuration de la profondeur maximale du spider
            requests.get(
                f"{ZAP_API_URL}/JSON/spider/action/setOptionMaxDepth/?apikey={API_KEY}&Integer=10",
                timeout=ZAP_TIMEOUT
            )
            
            logger.info("Contexte par défaut configuré (méthode 3)")
            
        return scope_success or context_success
        
    except Exception as e:
        logger.error(f"Erreur lors de l'ajout au scope: {str(e)}")
        return False

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Lance un scan ZAP sur l'URL spécifiée"""
    target_url = request.form.get('url')
    
    if not target_url:
        logger.warning("URL non spécifiée pour le scan")
        return jsonify({"status": "error", "message": "URL non spécifiée"})
    
    if not is_zap_running():
        logger.error("ZAP n'est pas en cours d'exécution")
        return jsonify({"status": "error", "message": "ZAP n'est pas en cours d'exécution"})
    
    try:
        logger.info(f"Lancement du scan sur {target_url} via OWASP ZAP")
        
        # Ajouter l'URL au scope
        scope_added = add_to_zap_scope(target_url)
        if not scope_added:
            logger.warning("Problème lors de l'ajout au scope, on continue quand même")
        
        # Essayer de définir quelques options utiles
        try:
            # Augmenter la profondeur du scan
            requests.get(f"{ZAP_API_URL}/JSON/spider/action/setOptionMaxDepth/?apikey={API_KEY}&Integer=10", timeout=ZAP_TIMEOUT)
            # Définir le nombre maximum de minutes du scan
            requests.get(f"{ZAP_API_URL}/JSON/spider/action/setOptionMaxDuration/?apikey={API_KEY}&Integer=60", timeout=ZAP_TIMEOUT)
            # Désactiver la vérification des certificats SSL
            requests.get(f"{ZAP_API_URL}/JSON/core/action/setOptionUseProxyChain/?apikey={API_KEY}&Boolean=false", timeout=ZAP_TIMEOUT)
            # Gérer les codes de réponse HTTP anormaux
            requests.get(f"{ZAP_API_URL}/JSON/core/action/setOptionHandleAbnormalHttpResponseCodes/?apikey={API_KEY}&Boolean=true", timeout=ZAP_TIMEOUT)
            
            logger.info("Options de scan configurées avec succès")
        except Exception as e:
            logger.warning(f"Erreur lors de la configuration des options: {str(e)}")
            
        # Lancer le Spider
        logger.info(f"Lancement du Spider sur {target_url}")
        spider_url = f"{ZAP_API_URL}/JSON/spider/action/scan/?apikey={API_KEY}&url={urllib.parse.quote(target_url)}&maxChildren=10&recurse=true&contextName=&subtreeOnly="
        spider_response = requests.get(spider_url, timeout=ZAP_TIMEOUT)
        
        if spider_response.status_code != 200:
            logger.error(f"Échec du lancement du Spider: {spider_response.text}")
            return jsonify({"status": "error", "message": "Échec du lancement du Spider", "details": spider_response.text})
        
        spider_data = spider_response.json()
        if "scan" not in spider_data:
            logger.error(f"Réponse ZAP invalide pour le Spider: {spider_data}")
            return jsonify({"status": "error", "message": "Réponse ZAP invalide", "details": spider_data})
            
        spider_id = spider_data.get("scan")
        logger.info(f"Spider lancé avec succès, ID: {spider_id}")
        
        # Attendre un peu pour laisser le temps au Spider de démarrer
        time.sleep(2)
        
        # Lancer le scan actif
        logger.info(f"Lancement du scan actif sur {target_url}")
        scan_url = f"{ZAP_API_URL}/JSON/ascan/action/scan/?apikey={API_KEY}&url={urllib.parse.quote(target_url)}&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=&contextId="
        scan_response = requests.get(scan_url, timeout=ZAP_TIMEOUT)
        
        if scan_response.status_code != 200:
            logger.error(f"Échec du lancement du scan actif: {scan_response.text}")
            return jsonify({"status": "error", "message": "Échec du lancement du scan actif", "details": scan_response.text})
        
        scan_data = scan_response.json()
        if "scan" not in scan_data:
            logger.error(f"Réponse ZAP invalide pour le scan actif: {scan_data}")
            return jsonify({"status": "error", "message": "Réponse ZAP invalide", "details": scan_data})
            
        scan_id = scan_data.get("scan")
        logger.info(f"Scan actif lancé avec succès, ID: {scan_id}")
        
        return jsonify({
            "status": "ok",
            "message": "Scan démarré avec succès",
            "spider_id": spider_id,
            "scan_id": scan_id
        })
        
    except requests.exceptions.ConnectionError:
        logger.error("Impossible de se connecter à ZAP pour le scan")
        return jsonify({
            "status": "error", 
            "message": "Impossible de se connecter à ZAP. Vérifiez qu'il est en cours d'exécution."
        })
    except requests.exceptions.Timeout:
        logger.error("Délai d'attente dépassé lors du scan")
        return jsonify({
            "status": "error",
            "message": "Délai d'attente dépassé lors de la connexion à ZAP"
        })
    except Exception as e:
        logger.error(f"Erreur lors du scan: {str(e)}")
        return jsonify({"status": "error", "message": f"Erreur: {str(e)}"})

@app.route('/scan_status', methods=['GET'])
def scan_status():
    """Renvoie le statut des scans en cours"""
    if not is_zap_running():
        logger.error("ZAP n'est pas en cours d'exécution (vérification de statut)")
        return jsonify({"status": "error", "message": "ZAP n'est pas en cours d'exécution"})
    
    try:
        # Obtenir le statut du scan actif
        scan_id = request.args.get('scan_id')
        spider_id = request.args.get('spider_id')
        
        status = {}
        
        # Vérifier le statut du Spider
        if spider_id:
            logger.info(f"Vérification du statut du Spider (ID: {spider_id})")
            spider_status_response = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/?apikey={API_KEY}&scanId={spider_id}", timeout=ZAP_TIMEOUT)
            if spider_status_response.status_code == 200:
                spider_status = spider_status_response.json().get("status", "0")
                status["spider"] = {"id": spider_id, "progress": spider_status}
                logger.info(f"Statut du Spider: {spider_status}%")
        
        # Vérifier le statut du scan actif
        if scan_id:
            logger.info(f"Vérification du statut du scan actif (ID: {scan_id})")
            scan_status_response = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/?apikey={API_KEY}&scanId={scan_id}", timeout=ZAP_TIMEOUT)
            if scan_status_response.status_code == 200:
                scan_status = scan_status_response.json().get("status", "0")
                status["scan"] = {"id": scan_id, "progress": scan_status}
                logger.info(f"Statut du scan actif: {scan_status}%")
        
        return jsonify({"status": "ok", "data": status})
    
    except requests.exceptions.ConnectionError:
        logger.error("Impossible de se connecter à ZAP pour vérifier le statut")
        return jsonify({
            "status": "error", 
            "message": "Impossible de se connecter à ZAP"
        })
    except requests.exceptions.Timeout:
        logger.error("Délai d'attente dépassé lors de la vérification du statut")
        return jsonify({
            "status": "error",
            "message": "Délai d'attente dépassé lors de la connexion à ZAP"
        })
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du statut: {str(e)}")
        return jsonify({"status": "error", "message": f"Erreur: {str(e)}"})

@app.route('/get_results', methods=['GET'])
def get_results():
    """Récupère les alertes de sécurité détectées par ZAP"""
    if not is_zap_running():
        logger.error("ZAP n'est pas en cours d'exécution (récupération des résultats)")
        return jsonify({"status": "error", "message": "ZAP n'est pas en cours d'exécution"})
    
    try:
        logger.info("Récupération des alertes de sécurité")
        
        # Obtenir toutes les alertes
        alerts_response = requests.get(f"{ZAP_API_URL}/JSON/alert/view/alerts/?apikey={API_KEY}&baseurl=&start=&count=&riskId=", timeout=ZAP_TIMEOUT)
        
        if alerts_response.status_code != 200:
            logger.error(f"Impossible de récupérer les alertes: {alerts_response.text}")
            return jsonify({
                "status": "error", 
                "message": "Impossible de récupérer les alertes", 
                "details": alerts_response.text
            })
        
        alerts_data = alerts_response.json()
        if "alerts" not in alerts_data:
            logger.error(f"Format de réponse ZAP invalide: {alerts_data}")
            return jsonify({"status": "error", "message": "Format de réponse ZAP invalide", "details": alerts_data})
            
        alerts = alerts_data.get("alerts", [])
        logger.info(f"Nombre d'alertes récupérées: {len(alerts)}")
        
        # Obtenir les sites pour construire des URLs complètes
        sites_response = requests.get(f"{ZAP_API_URL}/JSON/core/view/sites/?apikey={API_KEY}", timeout=ZAP_TIMEOUT)
        target_url = ""
        if sites_response.status_code == 200 and "sites" in sites_response.json():
            sites = sites_response.json().get("sites", [])
            if sites:
                target_url = sites[0]
                logger.info(f"Site cible identifié: {target_url}")
        
        # Traiter les alertes pour l'affichage
        processed_alerts = []
        for alert in alerts:
            vuln_name = alert.get("name", "Inconnue").replace(" ", "+")
            
            processed_alert = {
                "name": alert.get("name", "Inconnue"),
                "description": alert.get("description", ""),
                "risk": alert.get("risk", "Information"),
                "link": f"https://www.cvedetails.com/google-search-results.php?q={vuln_name}",
                "location": alert.get("url", "")
            }
            
            # S'assurer que la location est une URL complète
            if processed_alert["location"] and not processed_alert["location"].startswith("http"):
                processed_alert["location"] = target_url + processed_alert["location"]
            
            processed_alerts.append(processed_alert)
        
        return jsonify({"status": "ok", "alerts": processed_alerts})
    
    except requests.exceptions.ConnectionError:
        logger.error("Impossible de se connecter à ZAP pour récupérer les résultats")
        return jsonify({
            "status": "error", 
            "message": "Impossible de se connecter à ZAP. Vérifiez qu'il est en cours d'exécution."
        })
    except requests.exceptions.Timeout:
        logger.error("Délai d'attente dépassé lors de la récupération des résultats")
        return jsonify({
            "status": "error",
            "message": "Délai d'attente dépassé lors de la connexion à ZAP"
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des résultats: {str(e)}")
        return jsonify({"status": "error", "message": f"Erreur: {str(e)}"})

@app.route('/download_report/<report_type>', methods=['GET'])
def download_report(report_type):
    """Télécharge un rapport au format JSON ou HTML"""
    if not is_zap_running():
        logger.error("ZAP n'est pas en cours d'exécution (téléchargement de rapport)")
        return jsonify({"status": "error", "message": "ZAP n'est pas en cours d'exécution"})
    
    try:
        logger.info(f"Demande de téléchargement de rapport au format {report_type}")
        
        if report_type == 'json':
            # Récupérer le rapport JSON
            logger.info("Génération du rapport JSON")
            alerts_response = requests.get(f"{ZAP_API_URL}/JSON/alert/view/alerts/?apikey={API_KEY}", timeout=30)  # Timeout plus long pour le rapport
            
            if alerts_response.status_code != 200:
                logger.error(f"Impossible de générer le rapport JSON: {alerts_response.text}")
                return jsonify({
                    "status": "error", 
                    "message": "Impossible de générer le rapport JSON", 
                    "details": alerts_response.text
                })
            
            # Enregistrer le rapport
            report_path = os.path.join(os.getcwd(), "report.json")
            with open(report_path, "w") as f:
                json.dump(alerts_response.json(), f, indent=4)
            
            logger.info(f"Rapport JSON généré avec succès: {report_path}")
            return send_file(report_path, as_attachment=True)
            
        elif report_type == 'html':
            # Récupérer le rapport HTML
            logger.info("Génération du rapport HTML")
            html_response = requests.get(f"{ZAP_API_URL}/OTHER/core/other/htmlreport/?apikey={API_KEY}", timeout=30)  # Timeout plus long pour le rapport
            
            if html_response.status_code != 200:
                logger.error(f"Impossible de générer le rapport HTML: {html_response.text}")
                return jsonify({
                    "status": "error", 
                    "message": "Impossible de générer le rapport HTML", 
                    "details": html_response.text
                })
            
            # Enregistrer le rapport
            report_path = os.path.join(os.getcwd(), "report.html")
            with open(report_path, "wb") as f:
                f.write(html_response.content)
            
            logger.info(f"Rapport HTML généré avec succès: {report_path}")
            return send_file(report_path, as_attachment=True)
            
        else:
            logger.warning(f"Type de rapport non valide: {report_type}")
            return jsonify({"status": "error", "message": "Type de rapport non valide. Utilisez 'json' ou 'html'."})
    
    except requests.exceptions.ConnectionError:
        logger.error("Impossible de se connecter à ZAP pour générer le rapport")
        return jsonify({
            "status": "error", 
            "message": "Impossible de se connecter à ZAP. Vérifiez qu'il est en cours d'exécution."
        })
    except requests.exceptions.Timeout:
        logger.error("Délai d'attente dépassé lors de la génération du rapport")
        return jsonify({
            "status": "error",
            "message": "Délai d'attente dépassé lors de la génération du rapport. Le rapport peut être volumineux."
        })
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
        return jsonify({"status": "error", "message": f"Erreur: {str(e)}"})

if __name__ == '__main__':
    # Vérifier si ZAP est en cours d'exécution
    if not is_zap_running():
        print("AVERTISSEMENT: ZAP ne semble pas être en cours d'exécution sur le port 8080.")
        print("Assurez-vous que le service ZAP est démarré avant d'utiliser cette application.")
        print("Vous pouvez le démarrer avec: sudo systemctl start zap.service")
        print("Ou utilisez le script launch_zap_web.sh fourni.")
    else:
        print("ZAP est déjà en cours d'exécution sur le port 8080")
    
    # Créer le répertoire templates s'il n'existe pas
    templates_dir = os.path.join(os.getcwd(), 'templates')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
        print(f"Répertoire des templates créé: {templates_dir}")
    
    # Vérifier si le fichier index.html existe dans le répertoire templates
    index_path = os.path.join(templates_dir, 'index.html')
    if not os.path.exists(index_path):
        print("AVERTISSEMENT: Le fichier index.html n'existe pas dans le répertoire templates.")
        print("Assurez-vous de créer ce fichier avant de lancer l'application.")
    
    # Démarrer l'application Flask
    print("Démarrage de l'application web sur http://0.0.0.0:5004")
    app.run(debug=True, host='0.0.0.0', port=5004)
