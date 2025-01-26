#!/bin/bash

# Chemin vers le dossier Toolbox
TOOLBOX_DIR="$(pwd)"

# Lancer les sous-modules en arrière-plan
declare -a MODULES=("Python metasploit Webmin" "Python wireshark" "Python nmap" "Python owasp")

for module in "${MODULES[@]}"; do
    MODULE_PATH="$TOOLBOX_DIR/$module"
    if [ -f "$MODULE_PATH/app.py" ]; then
        echo "Lancement de $MODULE_PATH/app.py en arrière-plan..."
        (cd "$MODULE_PATH" && nohup python3 app.py > "$MODULE_PATH/app.log" 2>&1 &)
    else
        echo "main.py non trouvé dans $MODULE_PATH"
    fi
done

# Lancer le main.py dans le dossier courant
if [ -f "$TOOLBOX_DIR/main.py" ]; then
    echo "Lancement de main.py..."
    python3 "$TOOLBOX_DIR/main.py"
else
    echo "main.py non trouvé dans $TOOLBOX_DIR"
fi
