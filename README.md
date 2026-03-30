# Prediccion-de-Ataques-en-Honeypots

# 🛡️ Guía de Re-conexión al Honeypot en AWS

Este documento explica cómo volver a poner en marcha tu laboratorio de seguridad tras haberlo detenido.

---

## 1. Encender la Instancia en AWS

Antes de nada, el servidor físico debe estar encendido:

1. Accede a tu consola de AWS (EC2 Dashboard).
2. Ve a **Instances**.
3. Selecciona tu instancia (la que dice `ubuntu`).
4. Haz clic en **Instance State → Start Instance**.
5. ⚠️ **IMPORTANTE:** Espera 1-2 minutos y busca la **Public IPv4 address**. Anótala, porque **cambia cada vez que apagas y enciendes la máquina**.

---

## 2. Conectar por SSH (Puerto de Administración)

Recuerda que para administrar el servidor **NO usamos el puerto 22**, sino el **8080** que configuramos para que el honeypot no nos bloquee.

Abre tu terminal local y ejecuta:

```bash
ssh -i "tu_llave.pem" -p 8080 ubuntu@TU_NUEVA_IP_DE_AWS
```

> Sustituye `tu_llave.pem` por el nombre de tu archivo de clave y `TU_NUEVA_IP_DE_AWS` por la IP que acabas de copiar.

---

## 3. Levantar los Honeypots (Docker)

Una vez dentro de la terminal de Ubuntu:

1. Navega a la carpeta del proyecto:

```bash
cd ~/honeypots
```

2. Levanta los contenedores en segundo plano:

```bash
docker-compose up -d
```

3. Verifica que todo esté en `done` o `running`:

```bash
docker ps
```

---

## 4. Vigilancia de Ataques (Logs)

Para ver en tiempo real quién está intentando entrar en tu trampa, usa el visor de logs:

```bash
tail -f ~/honeypots/logs/cowrie/cowrie.json
```

> 💡 **Nota:** Si te da un error de `Permission denied`, recuerda que usamos el siguiente comando para dar permisos de escritura al contenedor:
>
> ```bash
> sudo chmod -R 777 ~/honeypots/logs
> ```