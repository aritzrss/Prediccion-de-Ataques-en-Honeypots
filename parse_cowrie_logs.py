#!/usr/bin/env python3
"""
parse_cowrie_logs.py
Procesa logs JSONL de Cowrie (honeypot SSH) y genera un CSV
clasificado por tipo de ataque, listo para entrenar modelos ML.

Etiquetas alineadas a los 7 grupos del simulador de ataques:
  G1 · recon                  – Reconocimiento y escaneo básico
  G2 · malware_deploy         – Descarga y ejecución de malware
  G3 · persistence            – Backdoors y persistencia
  G4 · privilege_escalation   – Escalada de privilegios
  G5 · exfiltration           – Robo de datos y exfiltración
  G6 · destruction            – Destrucción y ransomware
  G7 · lateral_movement       – Movimiento lateral y servicios
  --   credential_spray_success / credential_spray_failed (sin comandos)

Uso:
    python parse_cowrie_logs.py cowrie.json -o output.csv
    python parse_cowrie_logs.py cowrie.json          # genera cowrie_ml.csv
"""

import json
import csv
import argparse
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path


# ══════════════════════════════════════════════════════════════
#  SEÑALES POR GRUPO  (derivadas del simulador)
# ══════════════════════════════════════════════════════════════

# G1 – Reconocimiento y escaneo básico
G1_RECON = {
    "uname", "whoami", "id", "cat /proc/cpuinfo", "cat /etc/os-release",
    "free -m", "df -h", "cat /proc/mounts", "ps aux", "netstat -tulnp",
    "ifconfig", "ip a", "route -n", "arp -a", "ls -la /home",
    "cat /etc/passwd", "cat /etc/shadow", "cat /etc/group",
    "env", "set", "echo $path", "history", "cat ~/.bash_history",
    "cat /etc/hostname", "cat /etc/hosts", "cat /etc/resolv.conf",
    "enable", "system", "shell", "sh",
    # comandos de ruido del simulador (también son reconocimiento pasivo)
    "ls", "ls -la", "ls -lah", "ll", "pwd", "clear", "date",
    "w", "uptime", "who", "cat /etc/issue",
    "cat /var/log/auth.log", "cat /var/log/syslog",
}

# G2 – Descarga y ejecución de malware
# Requiere: descarga activa + ejecución en directorio volátil
G2_VOLATILE_DIRS = {"/tmp", "/var/tmp", "/dev/shm"}
G2_DOWNLOAD      = {"wget", "curl", "tftp"}
G2_EXEC          = {
    "chmod +x", "chmod 777", "chmod 0777",
    "./ ", "./mips", "./xmrig", "./backdoor", "./payload",
    "| bash", "|bash",
}
G2_INDICATORS = {
    "xmrig", "pool.com:3333", "botnet-c2", "payload.sh",
    "installer.sh", "mips.bot", "backdoor.elf",
    "pastebin.com/raw", ".tar.gz", ".elf",
}

# G3 – Persistencia / backdoors
G3_PERSISTENCE = {
    "useradd", "adduser", "chpasswd", "usermod -ag sudo",
    "authorized_keys", "chmod 600 ~/.ssh",
    "crontab", "/etc/crontab",
    "/etc/rc.local",
    ".bashrc", "source ~/.bashrc",
    "systemctl enable", "systemctl start",
    "alias sudo",
}

# G4 – Escalada de privilegios
G4_PRIVESC = {
    "sudo -l",
    "find / -perm -4000",
    "cat /etc/sudoers",
    "gcc exploit", "./exploit",
    "docker run -v /:/mnt", "chroot /mnt sh",
    "chmod 777 /etc/shadow", "ls -l /etc/shadow",
    "getcap -r",
    "grep failed",   # cat /var/log/auth.log | grep Failed
    "uname -r",
}

# G5 – Exfiltración de datos
G5_EXFIL = {
    "tar -czvf", "tar -czv",
    "zip -r",
    "curl -f", "curl --upload",
    "wget --post",
    "scp dump", "scp *.sql",
    "mysqldump",
    "find / -name '*.pem'", "find / -name '*.key'", "find / -name '*.ovpn'",
    "aws.pem",
    "wp-config.php", ".env",
    "dump.sql", "data.zip", "config_backup",
    "grep -i 'password'",
    "find /var/www",
}

# G6 – Destrucción y ransomware
G6_DESTRUCTION = {
    "rm -rf /var/log",
    "cat /dev/null > ~/.bash_history", "history -c",
    "kill -9",
    "leer_esto.txt", "encriptados", "paga", "btc",   # nota de rescate
    "dd if=/dev/zero", "dd if=/dev/urandom",
    "iptables -f", "iptables -x", "-p input accept",
    "echo c > /proc/sysrq-trigger",
    "chattr -i /etc/passwd", "rm -f /etc/passwd",
    "find /home -type f -name '*.txt'",
}

# G7 – Movimiento lateral y servicios expuestos
G7_LATERAL = {
    "nmap",
    "redis-cli",
    "psql -u postgres", "psql",
    "mongo --eval", "mongo",
    "ssh ", "scp ",
    "nc ", "ncat",
    "-p 22,80,443",
    "192.168.1.0/24",
}


# ══════════════════════════════════════════════════════════════
#  FUNCIONES DE DETECCIÓN
# ══════════════════════════════════════════════════════════════

def _match(cmds: list[str], signal_set: set) -> bool:
    """True si algún comando contiene cualquier señal del conjunto."""
    for cmd in cmds:
        for sig in signal_set:
            if sig in cmd:
                return True
    return False


def _is_malware_deploy(cmds: list[str]) -> bool:
    """
    G2: descarga activa + (ejecución directa | pipe a bash | dir volátil + chmod).
    También detecta indicadores directos de herramientas del simulador.
    """
    if any(ind in c for c in cmds for ind in G2_INDICATORS):
        return True
    pipe_bash   = any("| bash" in c or "|bash" in c for c in cmds)
    has_dl      = any(kw in c for c in cmds for kw in G2_DOWNLOAD)
    has_exec    = any(kw in c for c in cmds for kw in G2_EXEC)
    in_volatile = any(d in c for c in cmds for d in G2_VOLATILE_DIRS)
    return pipe_bash or (has_dl and (has_exec or in_volatile))


# ══════════════════════════════════════════════════════════════
#  CLASIFICADOR PRINCIPAL  (jerarquía de mayor a menor gravedad)
# ══════════════════════════════════════════════════════════════

def classify_attack(session: dict) -> str:
    raw_cmds = session.get("commands", [])
    cmds = [c.lower().strip() for c in raw_cmds if c.strip()]

    if not cmds:
        return "credential_spray_success" if session.get("login_success") \
               else "credential_spray_failed"

    if _match(cmds, G6_DESTRUCTION):
        return "destruction"

    if _match(cmds, G5_EXFIL):
        return "exfiltration"

    if _is_malware_deploy(cmds):
        return "malware_deploy"

    if _match(cmds, G4_PRIVESC):
        return "privilege_escalation"

    if _match(cmds, G3_PERSISTENCE):
        return "persistence"

    if _match(cmds, G7_LATERAL):
        return "lateral_movement"

    # G1 es el default cuando hay comandos pero ninguna señal más grave
    return "recon"


# ══════════════════════════════════════════════════════════════
#  FEATURES BOOLEANAS (una por grupo, directamente usables en ML)
# ══════════════════════════════════════════════════════════════

def compute_flags(cmds: list[str]) -> dict:
    return {
        "flag_recon":                int(_match(cmds, G1_RECON)),
        "flag_malware_deploy":       int(_is_malware_deploy(cmds)),
        "flag_persistence":          int(_match(cmds, G3_PERSISTENCE)),
        "flag_privilege_escalation": int(_match(cmds, G4_PRIVESC)),
        "flag_exfiltration":         int(_match(cmds, G5_EXFIL)),
        "flag_destruction":          int(_match(cmds, G6_DESTRUCTION)),
        "flag_lateral_movement":     int(_match(cmds, G7_LATERAL)),
    }


# ══════════════════════════════════════════════════════════════
#  PARSER DE SESIONES
# ══════════════════════════════════════════════════════════════

def parse_sessions(log_path: str) -> list[dict]:
    sessions: dict[str, dict] = defaultdict(lambda: {
        "session": "", "src_ip": "", "dst_ip": "",
        "dst_port": 0, "protocol": "ssh",
        "timestamp_start": "", "timestamp_end": "",
        "ssh_version": "", "hassh": "",
        "login_attempts": 0, "login_success": False,
        "username": "", "password": "",
        "commands": [], "files_downloaded": [],
        "terminal_width": 0, "terminal_height": 0,
        "duration_seconds": 0.0,
    })

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            sid = ev.get("session", "")
            if not sid:
                continue

            s  = sessions[sid]
            s["session"] = sid
            ts = ev.get("timestamp", "")

            if not s["timestamp_start"] or ts < s["timestamp_start"]:
                s["timestamp_start"] = ts
            if not s["timestamp_end"] or ts > s["timestamp_end"]:
                s["timestamp_end"] = ts

            eid = ev.get("eventid", "")

            if eid == "cowrie.session.connect":
                s["src_ip"]   = ev.get("src_ip", "")
                s["dst_ip"]   = ev.get("dst_ip", "")
                s["dst_port"] = ev.get("dst_port", 0)
                s["protocol"] = ev.get("protocol", "ssh")

            elif eid == "cowrie.client.version":
                s["ssh_version"] = ev.get("version", "")

            elif eid == "cowrie.client.kex":
                s["hassh"] = ev.get("hassh", "")

            elif eid in ("cowrie.login.success", "cowrie.login.failed"):
                s["login_attempts"] += 1
                if eid == "cowrie.login.success":
                    s["login_success"] = True
                    s["username"] = ev.get("username", "")
                    s["password"] = ev.get("password", "")

            elif eid == "cowrie.command.input":
                cmd = ev.get("input", "").strip()
                if cmd:
                    s["commands"].append(cmd)

            elif eid == "cowrie.session.file_download":
                url = ev.get("url", "") or ev.get("outfile", "")
                if url:
                    s["files_downloaded"].append(url)

            elif eid == "cowrie.client.size":
                s["terminal_width"]  = ev.get("width", 0)
                s["terminal_height"] = ev.get("height", 0)

    for s in sessions.values():
        try:
            t0 = datetime.fromisoformat(s["timestamp_start"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(s["timestamp_end"].replace("Z", "+00:00"))
            s["duration_seconds"] = round((t1 - t0).total_seconds(), 2)
        except Exception:
            s["duration_seconds"] = 0.0

    return list(sessions.values())


# ══════════════════════════════════════════════════════════════
#  CONSTRUCCIÓN DE FILAS CSV
# ══════════════════════════════════════════════════════════════

def build_csv_rows(sessions: list[dict]) -> list[dict]:
    rows = []
    for s in sessions:
        cmds    = s["commands"]
        cmds_lc = [c.lower().strip() for c in cmds if c.strip()]
        label   = classify_attack(s)
        flags   = compute_flags(cmds_lc)

        row = {
            # — Identificadores —
            "session_id":            s["session"],
            "timestamp":             s["timestamp_start"],
            "src_ip":                s["src_ip"],
            "dst_port":              s["dst_port"],
            # — Fingerprint de red —
            "ssh_version":           s["ssh_version"],
            "hassh":                 s["hassh"],
            # — Autenticación —
            "login_attempts":        s["login_attempts"],
            "login_success":         int(s["login_success"]),
            "username":              s["username"],
            "password":              s["password"],
            # — Comportamiento de sesión —
            "duration_seconds":      s["duration_seconds"],
            "terminal_width":        s["terminal_width"],
            "terminal_height":       s["terminal_height"],
            "num_commands":          len(cmds),
            "num_files_downloaded":  len(s["files_downloaded"]),
            # — Features booleanas por grupo (para ML supervisado) —
            **flags,
            # — Texto crudo (para NLP / embeddings) —
            "commands_raw":          " | ".join(cmds),
            "files_downloaded":      " | ".join(s["files_downloaded"]),
            # — Etiqueta objetivo —
            "attack_type":           label,
        }
        rows.append(row)
    return rows


# ══════════════════════════════════════════════════════════════
#  ESCRITURA CSV + RESUMEN
# ══════════════════════════════════════════════════════════════

LABEL_DESCRIPTIONS = {
    "recon":                    "G1 · Reconocimiento y escaneo básico",
    "malware_deploy":           "G2 · Descarga y ejecución de malware",
    "persistence":              "G3 · Backdoors y persistencia",
    "privilege_escalation":     "G4 · Escalada de privilegios",
    "exfiltration":             "G5 · Robo de datos y exfiltración",
    "destruction":              "G6 · Destrucción y ransomware",
    "lateral_movement":         "G7 · Movimiento lateral y servicios",
    "credential_spray_success": "–  · Credential spray (login sin comandos)",
    "credential_spray_failed":  "–  · Credential spray (autenticación fallida)",
}

def write_csv(rows: list[dict], output_path: str):
    if not rows:
        print("⚠️  No se encontraron sesiones en el log.", file=sys.stderr)
        return

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ CSV generado: {output_path}  ({len(rows)} sesiones)\n")
    counts = Counter(r["attack_type"] for r in rows)
    print("📊 Distribución de etiquetas:")
    for label, desc in LABEL_DESCRIPTIONS.items():
        n = counts.get(label, 0)
        if n == 0:
            continue
        pct = 100 * n / len(rows)
        print(f"   {desc:<52}  {n:>6}  ({pct:.1f}%)")


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Convierte logs JSONL de Cowrie en CSV clasificado para ML"
    )
    parser.add_argument("log_file", help="Ruta al archivo .json / .jsonl de Cowrie")
    parser.add_argument(
        "-o", "--output", default="cowrie_ml.csv",
        help="CSV de salida (default: cowrie_ml.csv)"
    )
    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"❌ Archivo no encontrado: {log_path}", file=sys.stderr)
        sys.exit(1)

    print(f"📂 Leyendo {log_path} …")
    sessions = parse_sessions(str(log_path))
    print(f"   → {len(sessions)} sesiones detectadas")

    rows = build_csv_rows(sessions)
    write_csv(rows, args.output)


if __name__ == "__main__":
    main()