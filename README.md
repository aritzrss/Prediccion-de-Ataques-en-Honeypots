# Prediccion-de-Ataques-en-Honeypots

## 🛡️ Guía de Re-conexión al Honeypot en AWS

Este documento explica cómo volver a poner en marcha tu laboratorio de seguridad tras haberlo detenido.

1. Encender la Instancia en AWS
Antes de nada, el servidor físico debe estar encendido:

Accede a tu consola de AWS (EC2 Dashboard).

Ve a Instances.

Selecciona tu instancia (la que dice ubuntu).

Haz clic en Instance State -> Start Instance.

IMPORTANTE: Espera 1-2 minutos y busca la Public IPv4 address. Anótala, porque cambia cada vez que apagas y enciendes la máquina.

2. Conectar por SSH (Puerto de Administración)
Recuerda que para administrar el servidor NO usamos el puerto 22, sino el 8080 que configuramos para que el honeypot no nos bloquee.

Abre tu terminal local y ejecuta:

Bash
ssh -i "tu_llave.pem" -p 8080 ubuntu@TU_NUEVA_IP_DE_AWS
(Sustituye tu_llave.pem por el nombre de tu archivo de clave y TU_NUEVA_IP_DE_AWS por la IP que acabas de copiar).

3. Levantar los Honeypots (Docker)
Una vez dentro de la terminal de Ubuntu:

Navega a la carpeta del proyecto:

Bash
cd ~/honeypots
Levanta los contenedores en segundo plano:

Bash
docker-compose up -d
Verifica que todo esté en "done" o "running":

Bash
docker ps
4. Vigilancia de Ataques (Logs)
Para ver en tiempo real quién está intentando entrar en tu trampa, usa el visor de logs:

Bash
tail -f ~/honeypots/logs/cowrie/cowrie.json
Nota: Si te da un error de "Permission denied", recuerda que usamos el comando sudo chmod -R 777 ~/honeypots/logs para dar permisos de escritura al contenedor.