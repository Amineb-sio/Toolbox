#!/bin/bash

# Script de démarrage rapide pour l'analyseur de trafic réseau
# Vérifie l'installation et démarre les services

echo "🌐 DÉMARRAGE DE L'ANALYSEUR DE TRAFIC RÉSEAU"
echo "=============================================="
echo ""

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages colorés
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier si on est dans le bon répertoire
if [ ! -f "main.py" ]; then
    print_error "Ce script doit être exécuté depuis le répertoire racine de la Toolbox"
    print_error "Répertoire actuel: $(pwd)"
    exit 1
fi

print_success "Répertoire Toolbox détecté: $(pwd)"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 non trouvé. Veuillez l'installer."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_success "Python détecté: $PYTHON_VERSION"

# Vérifier pip
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    print_error "pip non trouvé. Veuillez l'installer."
    exit 1
fi

print_success "pip disponible"

# Vérifier si l'analyseur réseau est installé
if [ ! -d "Python_network_analyzer" ]; then
    print_warning "Répertoire Python_network_analyzer non trouvé"
    print_status "Lancement de l'installation automatique..."
    
    if [ -f "setup_network_analyzer.py" ]; then
        python3 setup_network_analyzer.py
        if [ $? -ne 0 ]; then
            print_error "Échec de l'installation automatique"
            exit 1
        fi
    else
        print_error "setup_network_analyzer.py non trouvé"
        print_error "Veuillez installer manuellement l'analyseur réseau"
        exit 1
    fi
fi

print_success "Analyseur réseau installé"

# Vérifier les dépendances
print_status "Vérification des dépendances Python..."

REQUIRED_PACKAGES=("flask" "scapy" "pandas")
MISSING_PACKAGES=()

for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! python3 -c "import $package" &> /dev/null; then
        MISSING_PACKAGES+=($package)
    fi
done

if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    print_warning "Packages manquants: ${MISSING_PACKAGES[*]}"
    print_status "Installation des dépendances manquantes..."
    
    cd Python_network_analyzer
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        if [ $? -ne 0 ]; then
            print_error "Échec de l'installation des dépendances"
            exit 1
        fi
    else
        pip3 install flask scapy pandas geoip2
    fi
    cd ..
fi

print_success "Toutes les dépendances sont installées"

# Vérifier les permissions pour la capture de paquets
print_status "Vérification des permissions..."

if [ "$EUID" -eq 0 ]; then
    print_success "Exécution en tant que root - capture de paquets disponible"
    SUDO_CMD=""
else
    print_warning "Pas de privilèges root - capture limitée"
    print_status "Pour la capture complète, relancez avec: sudo $0"
    SUDO_CMD=""
fi

# Vérifier si les ports sont disponibles
print_status "Vérification des ports..."

check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        return 1
    else
        return 0
    fi
}

# Port analyseur réseau (5022)
if check_port 5022; then
    print_success "Port 5022 libre - Analyseur réseau peut démarrer"
    ANALYZER_PORT_FREE=true
else
    print_warning "Port 5022 utilisé - Analyseur réseau déjà actif?"
    ANALYZER_PORT_FREE=false
fi

# Menu de démarrage simplifié
echo ""
echo "🚀 DÉMARRAGE DE L'ANALYSEUR RÉSEAU"
echo "=================================="
echo "1. Démarrer l'analyseur réseau (port 5022)"
echo "2. Quitter"
echo ""

read -p "Choisissez une option (1-2): " choice

case $choice in
    1)
        print_status "Démarrage de l'analyseur réseau..."
        cd Python_network_analyzer
        if [ "$ANALYZER_PORT_FREE" = true ]; then
            print_success "Démarrage sur http://localhost:5022"
            print_success "Interface web: http://localhost:5022"
            print_status "Utilisez Ctrl+C pour arrêter le service"
            $SUDO_CMD python3 app.py
        else
            print_error "Port 5022 déjà utilisé"
            exit 1
        fi
        ;;
    
    2)
        print_status "Au revoir!"
        exit 0
        ;;
    
    *)
        print_error "Option invalide"
        exit 1
        ;;
esac

# Message de fin
echo ""
print_success "Démarrage terminé!"
print_status "Utilisez Ctrl+C pour arrêter les services"
