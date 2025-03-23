# Webmin Exploitation Tool

Cette application Flask permet de gérer un conteneur Docker Webmin et d'automatiser son exploitation via Metasploit.

1. **Lancer le conteneur webmin :**

il faut etre dans le dossier du module webmin et faire :

docker-compose up -d

2. **Accédez à l'application via votre navigateur pour etre sur:**

   ```
   https://localhost:10000
   ```
Vous allez apercevoir l'interface de webmin

3. **Exploitation de la vulnerabilite:**

Dans l'interface vous avez plusieurs champs :

LHOST : adresse ip de la machine ou on retrouve l'exploitation

RHOST : adresse ip local de la machine ou on retrouve l'exploitation

C'est la meme machine (on peut pas mettre des adresses identiques pour ses deux champs)

une fois l'exploitation terminé vous pouvez executer des commandes sur le conteneur
   


