FROM wordpress:latest

# Installe les outils nécessaires
RUN apt-get update && apt-get install -y wget unzip

# Télécharge et installe le plugin Ultimate Member
RUN wget -O /tmp/ultimate-member.zip https://downloads.wordpress.org/plugin/ultimate-member.2.8.2.zip \
    && unzip /tmp/ultimate-member.zip -d /usr/src/wordpress/wp-content/plugins/ \
    && rm /tmp/ultimate-member.zip

# Copie la sauvegarde WordPress dans le conteneur
COPY wordpress_data.tar.gz /tmp/

# Extraire le contenu dans /var/www/html (le dossier WordPress)
RUN tar -xzvf /tmp/wordpress_data.tar.gz -C /var/www/html && rm /tmp/wordpress_data.tar.gz
