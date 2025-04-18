#!/bin/bash

# Chemin vers le dossier Toolbox
TOOLBOX_DIR="$(pwd)"

# Arrêter les sous-modules en arrière-plan
declare -a MODULES=("Python metasploit Webmin" "Python wireshark" "Python nmap" "Python owasp" "Python wpscan" "Python gobuster" "Python tcpdump" "Python sqlmap" "Python hydra" "Python nikto" "Python johntheripper" "Python harvester" "Python subfinder" "Python autosecurite")

for module in "${MODULES[@]}"; do
    MODULE_PATH="$TOOLBOX_DIR/$module"
    if [ -f "$MODULE_PATH/app.py" ]; then
        echo "Arrêt de $MODULE_PATH/app.py..."
        # Trouver et tuer le processus en arrière-plan
        pkill -f "$MODULE_PATH/app.py"
    else
        echo "main.py non trouvé dans $MODULE_PATH"
    fi
done

# Arrêter le main.py dans le dossier courant
if [ -f "$TOOLBOX_DIR/main.py" ]; then
    echo "Arrêt de main.py..."
    # Trouver et tuer le processus en arrière-plan
    pkill -f "$TOOLBOX_DIR/main.py"
else
    echo "main.py non trouvé dans $TOOLBOX_DIR"
fi

echo "Tous les modules ont été arrêtés."
