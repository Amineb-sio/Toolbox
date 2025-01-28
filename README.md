# Toolbox Project

## Lancer la Toolbox avec Poetry

Pour exécuter la toolbox, tu dois utiliser Poetry qui gère les dépendances et l'environnement virtuel. Suis les étapes suivantes :

### Prérequis 

Assure-toi que Poetry est installé sur ta machine. Si ce n'est pas déjà fait, tu peux l'installer en suivant les instructions ici.

### Étapes

Cloner le repository : Si ce n'est pas déjà fait, commence par cloner ce repository sur ta machine locale :

git clone https://github.com/Amineb-sio/Toolbox.git
cd Toolbox

Installer les dépendances : Utilise Poetry pour installer les dépendances nécessaires à la toolbox :

poetry install

Lancer la toolbox : Pour démarrer la toolbox, utilise la commande suivante :

poetry run ./start_all.sh

Cela exécutera le script start_all.sh dans l'environnement virtuel géré par Poetry.