import sys
import subprocess
import sqlite3
import datetime
import os
import tempfile
import shutil
import logging

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'data.db')

SCRIPT_PATH = os.path.join(BASE_DIR, 'sherlock', 'sherlock_project', 'sherlock.py')
SCRIPT_NOM = "Sherlock"
SCRIPT_DESC = "Recherche de profils sur les réseaux sociaux"
PYTHON_EXE = sys.executable


def get_or_create_script(conn):
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM script WHERE path=?", (SCRIPT_PATH,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO script (path, nom, description) VALUES (?, ?, ?)", (SCRIPT_PATH, SCRIPT_NOM, SCRIPT_DESC))
        conn.commit()
        return cur.lastrowid
    except sqlite3.Error as e:
        logger.error("Erreur dans get_or_create_script: %s", e)
        raise


def create_execution(conn, id_script, username):
    try:
        cur = conn.cursor()
        now = datetime.datetime.now().isoformat()
        cur.execute(
            "INSERT INTO execution (id_script, date, cible_type, cible_id) VALUES (?, ?, ?, ?)",
            (id_script, now, 'user', None)
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.Error as e:
        logger.error("Erreur dans create_execution: %s", e)
        raise


def insert_result(conn, id_execution, username, url):
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO resultat (id_execution, username, type, valeur) VALUES (?, ?, ?, ?)",
            (id_execution, username, 'sherlock', url)
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error("Erreur dans insert_result: %s", e)
        raise


def run_sherlock(username):
    try:
        if not os.path.isfile(SCRIPT_PATH):
            raise FileNotFoundError(f"Script Sherlock introuvable: {SCRIPT_PATH}")

        logger.info("Connexion à la base de données: %s", DB_PATH)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON")

        id_script = get_or_create_script(conn)
        id_execution = create_execution(conn, id_script, username)

        print(f"Démarrage de la recherche pour l'utilisateur: {username}")

        # Création d'un dossier temporaire pour les fichiers CSV
        temp_dir = tempfile.mkdtemp()
        try:
            cmd = [
                PYTHON_EXE,
                "-u",
                SCRIPT_PATH,
                username,
                "--no-color",
                "--csv",
                "--folderoutput", temp_dir,
                "--timeout", "10",
                "--print-found"
            ]
            logger.info("Exécution de la commande: %s", ' '.join(cmd))

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                errors='replace'
            )
            for line in iter(proc.stdout.readline, ''):
                print(line, end='', flush=True)
                if "https://" in line:
                    url = line.split()[-1].strip()
                    insert_result(conn, id_execution, username, url)
            proc.stdout.close()
            proc.wait()

            print("\nRecherche terminée!")

        finally:
            shutil.rmtree(temp_dir)

    except sqlite3.Error as e:
        logger.error("Erreur SQLite: %s", e)
        raise
    except Exception as e:
        logger.error("Erreur inattendue: %s", e)
        raise
    finally:
        if 'conn' in locals():
            conn.close()
            logger.info("Connexion à la base de données fermée")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sherlock_scan.py <username>")
        sys.exit(1)
    run_sherlock(sys.argv[1])
