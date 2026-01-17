from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context, abort
import subprocess
import sqlite3
import os
import logging
import sys
import html
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data.db')
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')
PYTHON_EXE = sys.executable


def get_db_connection():
    try:
        logger.info("Tentative de connexion à la base de données: %s", DB_PATH)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        # Activer les clés étrangères
        conn.execute("PRAGMA foreign_keys = ON")
        # Activer le mode WAL pour de meilleures performances
        conn.execute("PRAGMA journal_mode = WAL")
        return conn
    except sqlite3.Error as e:
        logger.error("Erreur de connexion à la base de données: %s", e)
        raise


def init_db():
    try:
        logger.info("Initialisation de la base de données...")
        conn = sqlite3.connect(DB_PATH)
        init_path = os.path.join(BASE_DIR, 'init_db.sql')
        with open(init_path, 'r', encoding='utf-8') as f:
            conn.executescript(f.read())
        conn.close()
        logger.info("Base de données initialisée avec succès")
    except Exception as e:
        logger.error("Erreur lors de l'initialisation de la base de données: %s", e)
        raise


# Vérifier si la base de données existe et l'initialiser si nécessaire
if not os.path.exists(DB_PATH):
    init_db()


# Page d'accueil : dashboard
@app.route('/')
def dashboard():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Derniers réseaux
        cur.execute("SELECT ssid FROM reseau ORDER BY date_decouverte DESC, id DESC LIMIT 8")
        reseaux = cur.fetchall()
        logger.debug("Réseaux trouvés: %s", len(reseaux))

        # Derniers clients (IP + SSID)
        cur.execute("""
            SELECT client.ip, reseau.ssid FROM client
            LEFT JOIN reseau ON client.id_reseau = reseau.id
            ORDER BY client.date_decouverte DESC, client.id DESC LIMIT 8
        """)
        clients = cur.fetchall()
        logger.debug("Clients trouvés: %s", len(clients))

        # Derniers ports (IP + port)
        cur.execute("""
            SELECT client.ip, port.port FROM port
            LEFT JOIN client ON port.id_client = client.id
            ORDER BY port.date_decouverte DESC, port.id DESC LIMIT 8
        """)
        ports = cur.fetchall()
        logger.debug("Ports trouvés: %s", len(ports))

        # Derniers résultats Sherlock
        cur.execute("""
            SELECT r.username, r.valeur, e.date
            FROM resultat r
            JOIN execution e ON r.id_execution = e.id
            JOIN script s ON e.id_script = s.id
            WHERE s.nom = 'Sherlock'
            ORDER BY e.date DESC, r.id DESC LIMIT 8
        """)
        sherlock_results = cur.fetchall()
        logger.debug("Résultats Sherlock trouvés: %s", len(sherlock_results))

        conn.close()

        # Nombre d'outils : nombre de fichiers .py dans scripts/
        nb_outils = len([f for f in os.listdir(SCRIPTS_DIR) if f.endswith('.py') and not f.startswith('__')])
        logger.debug("Nombre d'outils: %s", nb_outils)

        # Nombre de mots de passe/users
        def count_lines(filename):
            try:
                if os.path.exists(filename):
                    with open(filename, 'r', encoding='utf-8', errors='replace') as f:
                        return sum(1 for _ in f)
                return 0
            except Exception as e:
                logger.error("Erreur lors de la lecture de %s: %s", filename, e)
                return 0

        nb_passwords = count_lines(os.path.join(BASE_DIR, 'password.txt'))
        nb_users = count_lines(os.path.join(BASE_DIR, 'user.txt'))
        logger.debug("Nombre de mots de passe: %s, Nombre d'utilisateurs: %s", nb_passwords, nb_users)

        return render_template(
            'dashboard.html',
            reseaux=reseaux,
            clients=clients,
            ports=ports,
            sherlock_results=sherlock_results,
            nb_outils=nb_outils,
            nb_passwords=nb_passwords,
            nb_users=nb_users
        )
    except Exception as e:
        logger.error("Erreur dans la route dashboard: %s", e)
        return render_template('error.html', error=str(e)), 500


def get_script_info(script_path):
    """Récupère les informations d'un script."""
    try:
        with open(script_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError as e:
        logger.warning("Impossible de lire le script %s: %s", script_path, e)
        content = ""

    # Extraction des métadonnées du script
    name = os.path.basename(script_path).replace('.py', '')
    description = "Script de hacking"  # Par défaut
    script_type = "Général"  # Par défaut

    # Recherche des métadonnées dans les commentaires
    for line in content.split('\n'):
        if line.startswith('# Description:'):
            description = line.replace('# Description:', '').strip()
        elif line.startswith('# Type:'):
            script_type = line.replace('# Type:', '').strip()

    return {
        'name': name,
        'description': description,
        'type': script_type,
        'filename': os.path.basename(script_path),
        'last_modified': datetime.fromtimestamp(os.path.getmtime(script_path)).strftime('%d/%m/%Y %H:%M')
    }


@app.route('/outilshacking')
def outilshacking():
    scripts = []

    # Scan du dossier scripts
    for filename in os.listdir(SCRIPTS_DIR):
        if filename.endswith('.py'):
            script_path = os.path.join(SCRIPTS_DIR, filename)
            script_info = get_script_info(script_path)
            scripts.append(script_info)
    scripts.sort(key=lambda item: item['name'].lower())

    return render_template('outilshacking.html', scripts=scripts)


def stream_command(cmd, cwd=None):
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=cwd,
            errors='replace'
        )
    except Exception as e:
        yield f"Erreur: {html.escape(str(e))}<br>"
        return

    for line in iter(process.stdout.readline, ''):
        safe_line = html.escape(line.rstrip('\r\n'))
        yield f"{safe_line}<br>" if safe_line else "<br>"
    process.stdout.close()
    returncode = process.wait()
    if returncode != 0:
        yield f"<br><span class=\"terminal-error\">Processus terminé avec le code {returncode}</span><br>"


@app.route('/run/<path:filename>', methods=['GET', 'POST'])
def run_script(filename):
    safe_name = os.path.basename(filename)
    if safe_name != filename or not safe_name.endswith('.py'):
        abort(404)

    script_path = os.path.join(SCRIPTS_DIR, safe_name)
    if not os.path.isfile(script_path):
        abort(404)

    # Mapping des scripts vers leurs interfaces spécifiques
    script_interfaces = {
        'discover.py': 'discover',
        'sherlock_scan.py': 'sherlock'
    }
    if safe_name in script_interfaces:
        return redirect(url_for(script_interfaces[safe_name]))

    if request.method == 'GET':
        script_info = get_script_info(script_path)
        return render_template('run_script.html', script=script_info)

    cmd = [PYTHON_EXE, '-u', script_path]
    return Response(stream_with_context(stream_command(cmd, cwd=BASE_DIR)), mimetype='text/html')


# Interface de découverte réseau (scan)
@app.route('/discover', methods=['GET', 'POST'])
def discover():
    if request.method == 'POST':
        subnet = request.form.get('subnet', '')
        ssid = request.form.get('ssid', '').strip()
        mode = request.form.get('mode', 'partial')
        action = request.form.get('action', '').lower()

        cmd = [PYTHON_EXE, '-u', os.path.join(SCRIPTS_DIR, 'discover.py')]
        if ssid:
            cmd.extend(['--ssid', ssid])
        if action == 'auto':
            cmd.append('--auto')
        else:
            if subnet:
                cmd.append(subnet)
            else:
                cmd.append('--auto')
            cmd.append('--full' if mode == 'full' else '--partial')

        return Response(stream_with_context(stream_command(cmd, cwd=BASE_DIR)), mimetype='text/html')

    # Pour GET, on affiche juste l'interface vide
    return render_template('discover.html', output="", mode='partial', ssid="")


@app.route('/sherlock', methods=['GET', 'POST'])
def sherlock():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            return Response("Aucun nom d'utilisateur fourni.<br>", mimetype='text/html', status=400)

        cmd = [PYTHON_EXE, '-u', os.path.join(SCRIPTS_DIR, 'sherlock_scan.py'), username]
        return Response(stream_with_context(stream_command(cmd, cwd=BASE_DIR)), mimetype='text/html')
    return render_template('sherlock.html', output="")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
