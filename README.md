Procédure pour lancer la toolbox

curl -sSL https://install.python-poetry.org | python3 - (installe poetry)

poetry --version (voir si poetry est bien installé)

poetry install (installe les dépendances)

poetry show pour voir les dépendances installé (ceux installés sont en bleu)

ip a (voir son ip sur l'interface eth0)

Remplacer par son ip dans le fichier main.py avec l'url "http://ip"


poetry run bash ./start_all.sh



Installer docker sur kali pour tester les conteneur avec certains outil : 

sudo apt install -y docker.io

sudo systemctl enable docker --now

sudo usermod -aG docker $USER



Installer docker-compose :

sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

sudo chmod +x /usr/local/bin/docker-compose

docker-compose --version

puis se mettre dans le dossier du module et faire :

docker-compose up -d

Pour les modules avec dockerfile :

docker-compose up --build -d




Mettre le clavier en francais sur kali :

setxkbmap fr 

sudo dpkg-reconfigure keyboard-configuration (choisir le premier pc)

ensuite choisir french azerty puis faire toujours entrer

tache : Mettre en place HTTPS avec un certificat SSL/TLS


