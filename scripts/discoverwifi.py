# Description: Scan Wi-Fi et enregistre les reseaux dans la base
# Type: Wi-Fi

import argparse
import datetime
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import uuid

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'data.db')


def detect_wifi_interface():
    sys_class_net = '/sys/class/net'
    if os.path.isdir(sys_class_net):
        for iface in os.listdir(sys_class_net):
            if os.path.isdir(os.path.join(sys_class_net, iface, 'wireless')):
                return iface
    return None


def normalize_security(value):
    if not value:
        return 'OPEN'
    value = value.strip().upper()
    if value in ('--', 'NONE', 'OPEN'):
        return 'OPEN'
    if 'WPA3' in value:
        return 'WPA3'
    if 'WPA2' in value or 'RSN' in value:
        return 'WPA2'
    if 'WPA' in value:
        return 'WPA'
    if 'WEP' in value or 'PRIVACY' in value:
        return 'WEP'
    return value


def run_command(cmd):
    try:
        return subprocess.check_output(cmd, text=True, errors='replace')
    except subprocess.CalledProcessError as exc:
        output = (exc.output or '').strip()
        message = output if output else str(exc)
        raise RuntimeError(message)


def scan_nmcli(interface):
    if shutil.which('nmcli') is None:
        raise RuntimeError("nmcli n'est pas disponible")

    cmd = [
        'nmcli',
        '--terse',
        '--separator', '|',
        '--fields', 'SSID,SECURITY,SIGNAL',
        'dev', 'wifi', 'list',
        '--rescan', 'yes'
    ]
    if interface:
        cmd.extend(['ifname', interface])

    output = run_command(cmd)
    networks = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split('|')
        ssid = parts[0].strip() if len(parts) > 0 else ''
        security = normalize_security(parts[1].strip() if len(parts) > 1 else '')
        signal = None
        if len(parts) > 2 and parts[2].strip().isdigit():
            signal = int(parts[2].strip())
        networks.append({
            'ssid': ssid,
            'security': security,
            'signal': signal,
            'signal_unit': '%',
            'bssid': None,
            'channel': None
        })
    return networks


def parse_iw_signal(line):
    match = re.search(r'signal:\s*([-\d\.]+)\s*dBm', line)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def scan_iw(interface):
    if shutil.which('iw') is None:
        raise RuntimeError("iw n'est pas disponible")
    if not interface:
        raise RuntimeError('Aucune interface Wi-Fi detectee')

    output = run_command(['iw', 'dev', interface, 'scan'])
    networks = []
    current = None

    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith('BSS '):
            if current:
                networks.append(current)
            bssid = line.split()[1].split('(')[0]
            current = {
                'ssid': '',
                'security': 'OPEN',
                'signal': None,
                'signal_unit': 'dBm',
                'bssid': bssid,
                'channel': None
            }
            continue
        if not current:
            continue
        if line.startswith('SSID:'):
            current['ssid'] = line.split('SSID:', 1)[1].strip()
        elif line.startswith('signal:'):
            current['signal'] = parse_iw_signal(line)
        elif line.startswith('capability:') and 'Privacy' in line:
            if current['security'] == 'OPEN':
                current['security'] = 'WEP'
        elif line.startswith('RSN:'):
            current['security'] = 'WPA2'
        elif line.startswith('WPA:') and current['security'] != 'WPA2':
            current['security'] = 'WPA'
        elif line.startswith('primary channel:'):
            parts = line.split(':', 1)
            if len(parts) == 2:
                current['channel'] = parts[1].strip()

    if current:
        networks.append(current)

    return networks


def parse_iwlist_signal(line):
    match = re.search(r'Signal level[=|:]\s*([-\d]+)', line)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def scan_iwlist(interface):
    if shutil.which('iwlist') is None:
        raise RuntimeError("iwlist n'est pas disponible")
    if not interface:
        raise RuntimeError('Aucune interface Wi-Fi detectee')

    output = run_command(['iwlist', interface, 'scanning'])
    networks = []
    current = None

    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith('Cell '):
            if current:
                networks.append(current)
            current = {
                'ssid': '',
                'security': 'OPEN',
                'signal': None,
                'signal_unit': 'dBm',
                'bssid': None,
                'channel': None
            }
            continue
        if not current:
            continue
        if 'ESSID:' in line:
            ssid = line.split('ESSID:', 1)[1].strip().strip('"')
            current['ssid'] = ssid
        elif 'Encryption key:' in line:
            if 'on' in line:
                current['security'] = 'WEP'
        elif 'IE: WPA2' in line:
            current['security'] = 'WPA2'
        elif 'IE: WPA' in line and current['security'] != 'WPA2':
            current['security'] = 'WPA'
        elif 'Signal level' in line:
            current['signal'] = parse_iwlist_signal(line)
        elif 'Channel:' in line:
            current['channel'] = line.split('Channel:', 1)[1].strip()

    if current:
        networks.append(current)

    return networks


def choose_method(requested):
    if requested != 'auto':
        return requested
    if shutil.which('nmcli'):
        return 'nmcli'
    if shutil.which('iw'):
        return 'iw'
    if shutil.which('iwlist'):
        return 'iwlist'
    raise RuntimeError('Aucun outil Wi-Fi trouve (nmcli, iw, iwlist).')


def save_to_db(networks, id_decouverte, date_now):
    if not networks:
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    seen = set()
    for net in networks:
        ssid = (net.get('ssid') or '').strip() or 'hidden'
        if ssid in seen:
            continue
        seen.add(ssid)
        protection = normalize_security(net.get('security'))
        cur.execute(
            "INSERT INTO reseau (ssid, password, protection, date_decouverte, id_decouverte) VALUES (?, ?, ?, ?, ?)",
            (ssid, '', protection, date_now, id_decouverte)
        )
    conn.commit()
    conn.close()


def format_network(net):
    ssid = net.get('ssid') or 'hidden'
    security = normalize_security(net.get('security'))
    signal = net.get('signal')
    unit = net.get('signal_unit') or ''
    signal_str = f"{signal}{unit}" if signal is not None else "-"
    return f"{ssid} | {security} | {signal_str}"


def main():
    parser = argparse.ArgumentParser(description='Scan Wi-Fi et enregistre les reseaux')
    parser.add_argument('--interface', '-i', help='Interface Wi-Fi (ex: wlan0)')
    parser.add_argument('--method', choices=['auto', 'nmcli', 'iw', 'iwlist'], default='auto')
    parser.add_argument('--open-only', action='store_true', help='Garder uniquement les reseaux ouverts')
    parser.add_argument('--limit', type=int, default=0, help='Limiter le nombre de resultats')
    parser.add_argument('--no-save', action='store_true', help='Ne pas enregistrer dans la base')
    args = parser.parse_args()

    interface = args.interface or detect_wifi_interface()
    try:
        method = choose_method(args.method)
    except RuntimeError as exc:
        print(f"Erreur: {exc}", flush=True)
        sys.exit(1)

    print(f"Methode: {method}", flush=True)
    if interface:
        print(f"Interface: {interface}", flush=True)

    try:
        if method == 'nmcli':
            networks = scan_nmcli(interface)
        elif method == 'iw':
            networks = scan_iw(interface)
        else:
            networks = scan_iwlist(interface)
    except RuntimeError as exc:
        print(f"Erreur: {exc}", flush=True)
        sys.exit(1)

    if args.open_only:
        networks = [net for net in networks if normalize_security(net.get('security')) == 'OPEN']

    networks.sort(key=lambda n: n.get('signal') if n.get('signal') is not None else -9999, reverse=True)

    if args.limit and args.limit > 0:
        networks = networks[:args.limit]

    print(f"Reseaux trouves: {len(networks)}", flush=True)
    for net in networks:
        print(format_network(net), flush=True)

    if not args.no_save:
        id_decouverte = str(uuid.uuid4())
        date_now = datetime.datetime.now().isoformat()
        save_to_db(networks, id_decouverte, date_now)


if __name__ == '__main__':
    main()
