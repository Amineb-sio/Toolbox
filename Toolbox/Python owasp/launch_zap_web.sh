#!/bin/bash

# Répertoire de ZAP (à modifier selon votre installation)
ZAP_DIR="/usr/share/zaproxy"
ZAP_SCRIPT="$ZAP_DIR/zap.sh"

# Configuration
ZAP_PORT=8080
ZAP_API_KEY="monapikey"
ZAP_LOG="/tmp/zap_daemon.log"
FLASK_APP_DIR="$(pwd)"

# Fonction pour vérifier si un port est déjà utilisé
check_port() {
    if nc -z localhost $1 2>/dev/null; then
        return 0  # Port est utilisé
    else
        return 1  # Port est libre
    fi
}

# Fonction pour attendre que ZAP soit prêt
wait_for_zap() {
    local max_attempts=30
    local attempt=0
    echo "Attente du démarrage de ZAP..."
    while ! nc -z localhost $ZAP_PORT 2>/dev/null; do
        sleep 1
        attempt=$((attempt+1))
        if [ $attempt -ge $max_attempts ]; then
            echo "Échec du démarrage de ZAP après $max_attempts secondes."
            echo "Vérifiez les logs: $ZAP_LOG"
            return 1
        fi
        echo -n "."
    done
    echo ""
    echo "ZAP est prêt!"
    return 0
}

# Vérifier si le script ZAP existe
if [ ! -f "$ZAP_SCRIPT" ]; then
    echo "ERREUR: Le script ZAP n'a pas été trouvé à l'emplacement $ZAP_SCRIPT"
    echo "Veuillez vérifier votre installation ou modifier le chemin dans ce script."
    exit 1
fi

# Vérifier si les répertoires existent
if [ ! -d "$FLASK_APP_DIR/templates" ]; then
    echo "Création du répertoire templates dans $FLASK_APP_DIR"
    mkdir -p "$FLASK_APP_DIR/templates"
fi

# Copier index.html dans le répertoire templates si nécessaire
if [ -f "$FLASK_APP_DIR/index.html" ] && [ ! -f "$FLASK_APP_DIR/templates/index.html" ]; then
    echo "Copie de index.html vers le répertoire templates"
    cp "$FLASK_APP_DIR/index.html" "$FLASK_APP_DIR/templates/index.html"
fi

# Vérifier si ZAP est déjà en cours d'exécution
if check_port $ZAP_PORT; then
    echo "OWASP ZAP est déjà en cours d'exécution sur le port $ZAP_PORT"
else
    echo "Démarrage d'OWASP ZAP..."
    # Lancer ZAP en arrière-plan avec log
    $ZAP_SCRIPT -daemon -port $ZAP_PORT -config api.key=$ZAP_API_KEY -config api.disablekey=false > $ZAP_LOG 2>&1 &
    ZAP_PID=$!
    
    # Attendre que ZAP soit prêt
    if ! wait_for_zap; then
        echo "Échec du démarrage de ZAP. Vérifiez les logs et votre installation."
        exit 1
    fi
    
    echo "ZAP démarré avec PID: $ZAP_PID"
fi

# Vérifier si Python et les dépendances sont installés
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERREUR: Python3 n'est pas installé. Veuillez l'installer."
    exit 1
fi

# Vérifier si pip est installé
if ! command -v pip3 >/dev/null 2>&1; then
    echo "AVERTISSEMENT: pip3 n'est pas installé. Il est recommandé de l'installer."
    echo "Sous Debian/Ubuntu: sudo apt install python3-pip"
    echo "Sous CentOS/RHEL: sudo yum install python3-pip"
else
    # Vérifier si Flask est installé
    if ! pip3 list | grep -i flask >/dev/null 2>&1; then
        echo "Flask n'est pas installé. Installation en cours..."
        pip3 install flask requests
    fi
fi

# Vérifier si le fichier owasp_zap_web.py existe
if [ ! -f "$FLASK_APP_DIR/owasp_zap_web.py" ]; then
    echo "ERREUR: Le fichier owasp_zap_web.py n'a pas été trouvé dans $FLASK_APP_DIR"
    echo "Veuillez vérifier que vous êtes dans le bon répertoire."
    exit 1
fi

# Vérifier les autorisations sur les fichiers
if [ ! -x "$FLASK_APP_DIR/owasp_zap_web.py" ]; then
    echo "Ajout des droits d'exécution à owasp_zap_web.py"
    chmod +x "$FLASK_APP_DIR/owasp_zap_web.py"
fi

# Lancer l'application Flask
echo "Démarrage de l'application web..."
cd "$FLASK_APP_DIR"
python3 owasp_zap_web.py

# Gérer la fermeture
cleanup() {
    echo "Arrêt du programme..."
    # Trouver le PID de l'application Flask et l'arrêter
    FLASK_PID=$(ps aux | grep "python3 owasp_zap_web.py" | grep -v grep | awk '{print $2}')
    if [ ! -z "$FLASK_PID" ]; then
        echo "Arrêt de l'application Flask (PID: $FLASK_PID)"
        kill $FLASK_PID 2>/dev/null || true
    fi
    
    # Ne pas arrêter ZAP automatiquement, car d'autres applications pourraient l'utiliser
    echo "Note: ZAP continue de s'exécuter en arrière-plan."
    echo "Pour l'arrêter manuellement, utilisez: pkill -f \"zap.sh\""
    
    exit 0
}

# Capture des signaux Ctrl+C pour nettoyer avant de quitter
trap cleanup SIGINT SIGTERM

# Attendre que l'application Flask se termine
wait
