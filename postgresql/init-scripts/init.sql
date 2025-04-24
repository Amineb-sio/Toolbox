-- Création des tables pour stocker les rapports
CREATE TABLE IF NOT EXISTS rapports (
    id SERIAL PRIMARY KEY,
    titre VARCHAR(255) NOT NULL,
    description TEXT,
    module VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    chemin_fichier VARCHAR(255) NOT NULL,
    date_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    utilisateur VARCHAR(100)
);

-- Table spécifique pour les rapports Wireshark
CREATE TABLE IF NOT EXISTS wireshark_rapports (
    id SERIAL PRIMARY KEY,
    rapport_id INTEGER REFERENCES rapports(id) ON DELETE CASCADE,
    nb_paquets INTEGER,
    protocoles_detectes TEXT,
    duree_capture VARCHAR(50),
    taille_capture BIGINT,
    details_additionnels TEXT
);

-- Table spécifique pour les rapports Nmap
CREATE TABLE IF NOT EXISTS nmap_rapports (
    id SERIAL PRIMARY KEY,
    rapport_id INTEGER REFERENCES rapports(id) ON DELETE CASCADE,
    nb_hosts_scanned INTEGER,
    ports_ouverts TEXT,
    systemes_detectes TEXT,
    services_detectes TEXT,
    vulnerabilites_trouvees TEXT
);

-- Ajoutez d'autres tables spécifiques aux modules selon vos besoins
-- Par exemple:

-- Table pour les rapports OWASP ZAP
CREATE TABLE IF NOT EXISTS owasp_rapports (
    id SERIAL PRIMARY KEY,
    rapport_id INTEGER REFERENCES rapports(id) ON DELETE CASCADE,
    cibles TEXT,
    nb_alertes INTEGER,
    risques_critiques INTEGER,
    risques_eleves INTEGER,
    risques_moyens INTEGER,
    risques_faibles INTEGER,
    details_vulnerabilites TEXT
);

-- Table pour les rapports SQLMap
CREATE TABLE IF NOT EXISTS sqlmap_rapports (
    id SERIAL PRIMARY KEY,
    rapport_id INTEGER REFERENCES rapports(id) ON DELETE CASCADE,
    url_cible TEXT,
    nb_injections_trouvees INTEGER,
    type_injections TEXT,
    db_type VARCHAR(50),
    tables_trouvees TEXT,
    details_exploitation TEXT
);

-- Table pour stocker les statistiques d'utilisation
CREATE TABLE IF NOT EXISTS statistiques_utilisation (
    id SERIAL PRIMARY KEY,
    module VARCHAR(50) NOT NULL,
    date_utilisation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    utilisateur VARCHAR(100),
    duree_utilisation INTEGER,  -- en secondes
    details JSON
);

-- Index pour améliorer les performances des requêtes
CREATE INDEX IF NOT EXISTS idx_rapports_module ON rapports(module);
CREATE INDEX IF NOT EXISTS idx_rapports_date ON rapports(date_creation);
CREATE INDEX IF NOT EXISTS idx_rapports_utilisateur ON rapports(utilisateur);

