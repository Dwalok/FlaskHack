DROP TABLE IF EXISTS port;
DROP TABLE IF EXISTS client;
DROP TABLE IF EXISTS reseau;
DROP TABLE IF EXISTS script;
DROP TABLE IF EXISTS execution;
DROP TABLE IF EXISTS resultat;

CREATE TABLE reseau (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT,
    password TEXT,
    protection TEXT,
    date_decouverte TEXT,
    id_decouverte TEXT
);

CREATE TABLE client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT,
    mac TEXT,
    ip TEXT,
    id_reseau INTEGER,
    date_decouverte TEXT,
    id_decouverte TEXT,
    FOREIGN KEY(id_reseau) REFERENCES reseau(id)
);

CREATE TABLE port (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_client INTEGER,
    port INTEGER,
    protocole TEXT,
    services TEXT,
    date_decouverte TEXT,
    id_decouverte TEXT,
    etat TEXT,
    FOREIGN KEY(id_client) REFERENCES client(id)
);

CREATE TABLE script (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT,
    nom TEXT,
    description TEXT
);

CREATE TABLE execution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_script INTEGER,
    date TEXT,
    cible_type TEXT,
    cible_id INTEGER,
    FOREIGN KEY(id_script) REFERENCES script(id)
);

CREATE TABLE resultat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_execution INTEGER,
    username TEXT,
    type TEXT,
    valeur TEXT,
    FOREIGN KEY(id_execution) REFERENCES execution(id)
);