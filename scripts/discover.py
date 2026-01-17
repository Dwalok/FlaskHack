import sys
import subprocess
import sqlite3
import datetime
import uuid
import re
import os
import socket
import shutil
import xml.etree.ElementTree as ET

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'data.db')


def insert_reseau(conn, ssid, password, protection, date_decouverte, id_decouverte):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reseau (ssid, password, protection, date_decouverte, id_decouverte) VALUES (?, ?, ?, ?, ?)",
        (ssid, password, protection, date_decouverte, id_decouverte)
    )
    conn.commit()
    return cur.lastrowid


def insert_client(conn, nom, mac, ip, id_reseau, date_decouverte, id_decouverte):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO client (nom, mac, ip, id_reseau, date_decouverte, id_decouverte) VALUES (?, ?, ?, ?, ?, ?)",
        (nom, mac, ip, id_reseau, date_decouverte, id_decouverte)
    )
    conn.commit()
    return cur.lastrowid


def insert_port(conn, id_client, port, protocole, services, date_decouverte, id_decouverte, etat=None):
    cur = conn.cursor()
    if etat is not None:
        cur.execute(
            "INSERT INTO port (id_client, port, protocole, services, date_decouverte, id_decouverte, etat) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (id_client, port, protocole, services, date_decouverte, id_decouverte, etat)
        )
    else:
        cur.execute(
            "INSERT INTO port (id_client, port, protocole, services, date_decouverte, id_decouverte) VALUES (?, ?, ?, ?, ?, ?)",
            (id_client, port, protocole, services, date_decouverte, id_decouverte)
        )
    conn.commit()
    return cur.lastrowid


def resolve_nmap_path():
    env_path = os.environ.get("NMAP_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    which_path = shutil.which("nmap")
    if which_path:
        return which_path

    if os.name == "nt":
        candidates = [
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Nmap", "nmap.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Nmap", "nmap.exe")
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate

    raise RuntimeError(
        "La commande 'nmap' est introuvable. Installe-la, ajoute-la au PATH, "
        "ou définis la variable d'environnement NMAP_PATH."
    )


def auto_detect_subnet():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
        return subnet
    except Exception:
        pass

    if os.name == 'posix':
        try:
            ip = subprocess.check_output("hostname -I", shell=True).decode().split()[0]
            subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
            return subnet
        except Exception:
            return "192.168.1.0/24"

    return "192.168.1.0/24"


def extract_ipv4(text):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return match.group(0) if match else None


def parse_nmap_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    clients = []
    seen = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                if ip and ip not in seen:
                    clients.append(ip)
                    seen.add(ip)
    return clients


def pop_flag_value(args, flag):
    for i, arg in enumerate(args):
        if arg.startswith(flag + "="):
            value = arg.split("=", 1)[1]
            del args[i]
            return value
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            value = args[idx + 1]
            del args[idx:idx + 2]
            return value
        del args[idx]
    return None


def find_clients(subnet, nmap_path):
    xml_output = ""
    try:
        xml_output = subprocess.check_output(
            [nmap_path, '-sn', '-oX', '-', subnet],
            text=True,
            errors='replace'
        )
    except subprocess.CalledProcessError as exc:
        xml_output = exc.output or ""

    clients = parse_nmap_xml(xml_output)
    if clients is not None:
        return clients

    result = subprocess.check_output([nmap_path, '-sn', subnet], text=True, errors='replace')
    clients = []
    seen = set()
    for line in result.splitlines():
        if "Nmap scan report for" in line:
            ip = extract_ipv4(line)
            if ip and ip not in seen:
                clients.append(ip)
                seen.add(ip)
    return clients


def scan_ports_and_parse(ip, ports, nmap_path):
    if ports:
        cmd = [nmap_path, '-p', ports, '-T4', '-oN', '-', ip]
    else:
        cmd = [nmap_path, '-p-', '-T4', '-oN', '-', ip]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        errors='replace'
    )
    port_results = []
    capture = False
    for line in iter(proc.stdout.readline, ''):
        print(line, end='', flush=True)
        line = line.strip()
        if line.startswith("PORT"):
            capture = True
            continue
        if capture:
            # On ne s'arrête plus à la première ligne vide, on continue tant que la ligne ressemble à un port
            if re.match(r"^\d+/\w+", line):
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    port = int(port_proto[0])
                    protocole = port_proto[1]
                    etat = parts[1]
                    service = parts[2]
                    port_results.append((port, protocole, service, etat))
            else:
                # On sort de la section ports si la ligne ne correspond plus
                if line == "" or not line[0].isdigit():
                    break
    proc.stdout.close()
    proc.wait()
    return port_results


def parse_netsh_ssid(output):
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if "ssid" in key and "bssid" not in key:
            return value
    return None


def get_current_ssid():
    if os.name == "nt":
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True,
                errors="replace"
            )
            ssid = parse_netsh_ssid(output)
            if ssid:
                return ssid
        except Exception:
            return "inconnu"
        return "inconnu"

    try:
        # Pour Linux avec NetworkManager
        if shutil.which("nmcli"):
            ssid = subprocess.check_output(
                "nmcli -t -f active,ssid dev wifi | egrep '^yes' | cut -d: -f2",
                shell=True,
                text=True,
                errors="replace"
            ).strip()
            if ssid:
                return ssid
    except Exception:
        pass
    try:
        # Pour MacOS
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.isfile(airport_path):
            ssid = subprocess.check_output(
                f"\"{airport_path}\" -I | awk '/ SSID/ {{print $2}}'",
                shell=True,
                text=True,
                errors="replace"
            ).strip()
            if ssid:
                return ssid
    except Exception:
        pass
    return "inconnu"


def get_or_create_reseau(conn, ssid, date_decouverte, id_decouverte):
    cur = conn.cursor()
    cur.execute("SELECT id FROM reseau WHERE ssid=? AND date_decouverte=?", (ssid, date_decouverte))
    row = cur.fetchone()
    if row:
        return row[0]
    return insert_reseau(conn, ssid, "", "", date_decouverte, id_decouverte)


def main():
    args = sys.argv[1:]
    ssid_override = pop_flag_value(args, "--ssid")
    mode = "partial"
    if "--full" in args:
        mode = "full"
    elif "--partial" in args:
        mode = "partial"

    auto_mode = "--auto" in args or "auto" in args
    explicit_subnet = next((arg for arg in args if not arg.startswith("--")), None)

    if not args:
        subnet = auto_detect_subnet()
        print(subnet, flush=True)
        return

    if auto_mode and not explicit_subnet and "--full" not in args and "--partial" not in args:
        subnet = auto_detect_subnet()
        print(subnet, flush=True)
        return

    if explicit_subnet:
        subnet = explicit_subnet
    elif auto_mode:
        subnet = auto_detect_subnet()
    else:
        print("Erreur: aucun sous-réseau fourni.", flush=True)
        sys.exit(1)

    try:
        nmap_path = resolve_nmap_path()
    except RuntimeError as exc:
        print(f"Erreur: {exc}", flush=True)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    id_decouverte = str(uuid.uuid4())
    date_now = datetime.datetime.now().isoformat()

    # Détection du SSID courant ou saisie utilisateur
    ssid = ssid_override.strip() if ssid_override else get_current_ssid()
    if not ssid:
        ssid = "inconnu"
    id_reseau = get_or_create_reseau(conn, ssid=ssid, date_decouverte=date_now, id_decouverte=id_decouverte)

    print(f"Découverte des clients sur {subnet}...\n", flush=True)
    clients = find_clients(subnet, nmap_path)
    print(f"Clients trouvés ({len(clients)}) : {', '.join(clients)}\n", flush=True)
    ports = "22,80,443,8080,8443,21,23,25,110,139,445,3389" if mode == "partial" else None

    for ip in clients:
        print(f"\nScan des ports pour {ip} :", flush=True)
        id_client = insert_client(conn, nom="", mac="", ip=ip, id_reseau=id_reseau, date_decouverte=date_now, id_decouverte=id_decouverte)
        port_results = scan_ports_and_parse(ip, ports, nmap_path)
        for port, protocole, service, etat in port_results:
            insert_port(conn, id_client, port, protocole, service, date_now, id_decouverte, etat)
        print('-' * 40, flush=True)

    conn.close()


if __name__ == "__main__":
    main()
