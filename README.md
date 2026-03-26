# CENTINELA – Monitor de Seguridad para Contenedores Docker

CENTINELA es un sistema de monitorización de seguridad diseñado para correr junto a tus contenedores Docker y alertarte en tiempo real cuando ocurre algo sospechoso: ejecuciones de comandos inesperadas, cambios en archivos críticos, picos de tráfico de red, procesos maliciosos, y más.

---

## Tabla de contenidos

1. [Arquitectura general](#1-arquitectura-general)
2. [Requisitos previos](#2-requisitos-previos)
3. [Instalación y despliegue](#3-instalación-y-despliegue)
4. [Requisitos críticos en producción (Linux)](#4-️-requisitos-críticos-en-producción-linux)
5. [Guía de configuración](#5-guía-de-configuración)
6. [Configuración específica para Coolify](#6-configuración-específica-para-coolify)
7. [Cómo funcionan las alertas](#7-cómo-funcionan-las-alertas)
8. [Gestión de la base de datos](#8-gestión-de-la-base-de-datos)
9. [Archivos de log](#9-archivos-de-log)
10. [Solución de problemas](#10-solución-de-problemas)
11. [Hardening de seguridad](#11-hardening-de-seguridad)
12. [Hoja de ruta](#12-hoja-de-ruta)

---

## 1. Arquitectura general

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HOST LINUX                                  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Docker Engine                              │  │
│  │                                                               │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │  │
│  │  │  wordpress  │  │  laravel-   │  │  otro-contenedor   │   │  │
│  │  │   -tienda   │  │    api      │  │                    │   │  │
│  │  └──────┬──────┘  └──────┬──────┘  └────────┬───────────┘   │  │
│  │         │                │                   │               │  │
│  │  ┌──────▼────────────────▼───────────────────▼───────────┐  │  │
│  │  │              Docker Events API (/var/run/docker.sock)  │  │  │
│  │  └──────────────────────────┬────────────────────────────┘  │  │
│  │                             │                               │  │
│  │  ┌──────────────────────────▼────────────────────────────┐  │  │
│  │  │                   CENTINELA                           │  │  │
│  │  │                                                       │  │  │
│  │  │  ┌─────────────────┐   ┌──────────────────────────┐  │  │  │
│  │  │  │  DockerEvent    │   │   SecurityAudit          │  │  │  │
│  │  │  │  Monitor        │──▶│   Monitor                │  │  │  │
│  │  │  └────────┬────────┘   └──────────────────────────┘  │  │  │
│  │  │           │                                           │  │  │
│  │  │  ┌────────▼────────┐   ┌──────────────────────────┐  │  │  │
│  │  │  │  Process        │   │   Network                │  │  │  │
│  │  │  │  Monitor        │   │   Monitor                │  │  │  │
│  │  │  └─────────────────┘   └──────────────────────────┘  │  │  │
│  │  │                                                       │  │  │
│  │  │  ┌─────────────────┐   ┌──────────────────────────┐  │  │  │
│  │  │  │  Filesystem     │   │   Alert                  │  │  │  │
│  │  │  │  Monitor        │──▶│   Manager                │  │  │  │
│  │  │  └─────────────────┘   └────────────┬─────────────┘  │  │  │
│  │  │                                      │                │  │  │
│  │  │  ┌─────────────────────────────────┐ │                │  │  │
│  │  │  │   SQLite / PostgreSQL DB        │ │                │  │  │
│  │  │  │   (incidentes + baselines)      │ │                │  │  │
│  │  │  └─────────────────────────────────┘ │                │  │  │
│  │  └──────────────────────────────────────┘                │  │  │
│  │                                          │                │  │  │
│  └──────────────────────────────────────────┼────────────────┘  │
│                                             │                    │
└─────────────────────────────────────────────┼────────────────────┘
                                              │
              ┌───────────────────────────────▼────────────────────┐
              │                  Canales de alerta                  │
              │                                                     │
              │  📧 Email (SMTP)    🔗 Webhook HTTP    💬 WhatsApp  │
              └─────────────────────────────────────────────────────┘
```

### Componentes principales

| Componente | Descripción |
|---|---|
| `DockerEventMonitor` | Escucha el stream de eventos de Docker (exec, start, stop, die, restart). Es el hub central que dispara los demás monitores. |
| `ProcessMonitor` | Analiza `/proc` dentro de los contenedores buscando procesos sospechosos (shells, herramientas de hacking, miners). |
| `NetworkMonitor` | Muestrea contadores de tráfico. Aprende el baseline normal durante el periodo de aprendizaje y alerta en picos o destinos nuevos. |
| `FilesystemMonitor` | Usa inotify para detectar cambios en tiempo real en rutas críticas (wp-config.php, .env, uploads/). |
| `SecurityAuditMonitor` | Audita la configuración de seguridad de cada contenedor (usuario root, capabilities peligrosas, puertos expuestos, imagen desactualizada). |
| `AlertManager` | Gestiona el enrutamiento de alertas, el cooldown anti-flood, y la entrega por email/webhook/WhatsApp. |
| `IncidentRepository` | Persiste todos los incidentes en SQLite (o PostgreSQL). Sirve de historial y evita alertas duplicadas. |
| `ProjectRegistry` | Carga los ficheros YAML de proyectos y resuelve qué contenedor pertenece a qué proyecto. |

---

## 2. Requisitos previos

### Sistema operativo
- **Linux** (obligatorio). CENTINELA usa inotify y `/proc`, que son específicos de Linux.
- Kernel 4.x o superior recomendado.
- Probado en Ubuntu 22.04 LTS, Debian 12, Rocky Linux 9.

### Software
- **Docker Engine** 20.10 o superior
- **Docker Compose** v2 (el plugin `docker compose`, no el antiguo `docker-compose`)
- **Git** para clonar el repositorio

### Recursos del host
- RAM mínima para CENTINELA: 64 MB (límite configurado en 256 MB)
- CPU: menos del 5% en condiciones normales
- Disco: ~50 MB para la imagen + crecimiento de la base de datos (~1 MB/día típico)

### Para alertas de email
- Una cuenta de Gmail con una **Contraseña de aplicación** configurada (no la contraseña normal de la cuenta). Ver: [Contraseñas de aplicación de Google](https://support.google.com/accounts/answer/185833).
- O cualquier servidor SMTP compatible con STARTTLS.

---

## 3. Instalación y despliegue

### Paso 1: Clonar el repositorio

```bash
git clone https://github.com/tuusuario/centinela.git
cd centinela
```

### Paso 2: Preparar los directorios de datos

```bash
mkdir -p data logs
```

### Paso 3: Configurar las variables de entorno

```bash
cp .env.example .env
nano .env
```

Como mínimo, configura la zona horaria:

```env
TZ=Europe/Madrid
CENTINELA_LOG_LEVEL=INFO
```

### Paso 4: Editar la configuración global

```bash
cp config/centinela.yml config/centinela.yml.bak   # copia de seguridad
nano config/centinela.yml
```

Secciones obligatorias a revisar:
- `smtp`: tus credenciales de correo
- `default_alerts.emails`: a quién enviar alertas por defecto
- `monitoring`: ajusta los intervalos a tu carga de trabajo

### Paso 5: Crear la configuración de tu proyecto

```bash
cp config/projects/wordpress-example.yml config/projects/mi-proyecto.yml
nano config/projects/mi-proyecto.yml
```

Lo mínimo indispensable:
```yaml
name: "mi-proyecto"
type: wordpress        # o laravel, o generic
container_name: "nombre-exacto-del-contenedor"
app_root: /var/www/html
alerts:
  emails:
    - tu@email.com
enabled: true
```

### Paso 6: Construir y arrancar

```bash
# Construir la imagen
docker compose build

# Arrancar en segundo plano
docker compose up -d

# Verificar que arranca bien
docker compose logs -f centinela
```

En el arranque deberías ver algo como:

```
2024-01-15T10:23:01 [INFO] centinela.main – CENTINELA starting up – logging initialised.
2024-01-15T10:23:01 [INFO] centinela.main – Docker client connected successfully.
2024-01-15T10:23:01 [INFO] centinela.main – Project registry loaded – 2 project(s) tracked.
2024-01-15T10:23:02 [INFO] centinela.main – Startup: running security audit for container wordpress-tienda
2024-01-15T10:23:04 [INFO] centinela.main – All monitors started. CENTINELA is watching 2 project(s).
```

### Paso 7: Verificar el healthcheck

```bash
docker inspect centinela | grep -A 5 '"Health"'
```

El estado debe ser `"healthy"` después de 30 segundos.

### Actualizar CENTINELA

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

---

## 4. ⚠️ Requisitos críticos en producción (Linux)

### 1. Límite de inotify watchers

Centinela usa inotify para monitorizar el filesystem de los contenedores en tiempo real.
Linux tiene un límite global de watchers. Con muchos proyectos, este límite puede agotarse,
provocando que otras aplicaciones del servidor (incluido Coolify) fallen silenciosamente.

**Verificar el límite actual:**
```bash
cat /proc/sys/fs/inotify/max_user_watches
# Valor típico: 8192 — insuficiente para producción
```

**Aumentar el límite de forma permanente:**
```bash
echo "fs.inotify.max_user_watches = 524288" >> /etc/sysctl.conf
echo "fs.inotify.max_instances = 512" >> /etc/sysctl.conf
sysctl -p
```

**Regla general:** reservar ~10 watches por proyecto (7 rutas críticas + margen).
Para 100 proyectos: mínimo 1000 watches. El valor 524288 es más que suficiente.

### 2. Docker socket

En producción Linux, Centinela necesita acceso de **escritura** al socket Docker
para poder ejecutar `docker exec` en los chequeos de filesystem:

```yaml
# docker-compose.yml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:rw  # necesario para docker exec
```

Alternativa más segura con capabilities específicas en lugar de `privileged: true`:
```yaml
cap_add:
  - SYS_PTRACE
  - DAC_READ_SEARCH
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
privileged: false
```

### 3. Variables de entorno recomendadas

```bash
CENTINELA_WEB_USER=admin          # usuario del panel web
CENTINELA_WEB_PASS=tu_password    # contraseña del panel web (cambiar obligatoriamente)
CENTINELA_WEB_PORT=8080           # puerto del panel (cambiar si hay conflicto)
TZ=Europe/Madrid                   # zona horaria
PYTHONUTF8=1                       # encoding correcto en Linux también
```

---

## 5. Guía de configuración

### Estructura de ficheros

```
config/
├── centinela.yml          # Configuración global (SMTP, umbrales, intervalos)
└── projects/
    ├── wordpress-tienda.yml
    ├── laravel-api.yml
    └── otro-proyecto.yml
```

### centinela.yml: secciones clave

#### `storage`
```yaml
storage:
  db_url: "sqlite:////app/data/centinela.db"
  log_dir: /app/logs
  log_max_bytes: 10485760   # 10 MB por fichero
  log_backup_count: 5       # Mantener 5 ficheros rotados
```

#### `smtp`
```yaml
smtp:
  host: smtp.gmail.com
  port: 587
  user: "centinela@tudominio.com"
  password: "contraseña-de-aplicación"
  from: "CENTINELA <centinela@tudominio.com>"
  tls: true
  ssl: false
```

Para Gmail, genera una **contraseña de aplicación** en:
`Cuenta de Google → Seguridad → Contraseñas de aplicación`

#### `alert_cooldown`
Evita el spam de alertas repitiendo la misma alarma:

```yaml
alert_cooldown:
  DOCKER_EVENT_EXEC: 120    # No repetir alertas de exec en 2 minutos
  PROCESS_SUSPICIOUS: 120
  NETWORK_SPIKE: 300
  FILESYSTEM_CHANGE: 600    # 10 minutos entre alertas de filesystem
  default: 300
```

#### `monitoring` – intervalos de comprobación
```yaml
monitoring:
  network_sample_interval: 300      # Cada 5 min muestrea el tráfico
  process_check_interval: 60        # Cada 1 min escanea procesos
  security_audit_interval: 3600     # Auditoría completa cada hora
  fs_permission_check_interval: 1800
```

### Ficheros de proyecto

#### Detección de contenedores

CENTINELA ofrece tres estrategias para asociar un fichero de configuración con un contenedor. Usa **solo una** de las tres:

```yaml
# Estrategia 1: nombre exacto (más simple, recomendada para docker-compose)
container_name: "wordpress-tienda"

# Estrategia 2: etiqueta Docker (recomendada para Coolify)
container_label: "coolify.name=mi-tienda"

# Estrategia 3: prefijo de nombre (útil si Coolify añade sufijos aleatorios)
container_name_prefix: "tienda-wp-"
```

#### `critical_paths` vs `exclude_paths`

- `critical_paths`: cualquier cambio en estas rutas (relativas a `app_root`) genera una alerta de severidad alta.
- `exclude_paths`: estas rutas se ignoran completamente (útil para cachés de alta actividad).

#### `deployment_windows`

Suprime alertas de cambios en el sistema de ficheros durante ventanas de despliegue conocidas:

```yaml
deployment_windows:
  - start: "02:00"
    end: "05:00"
    days:
      - tuesday
      - thursday
```

Los eventos de Docker (exec, restart) **no** se suprimen nunca, incluso en ventanas de despliegue.

---

## 6. Configuración específica para Coolify

[Coolify](https://coolify.io) es una plataforma PaaS self-hosted que gestiona aplicaciones en Docker. CENTINELA se integra perfectamente con Coolify.

### Encontrar el nombre del contenedor en Coolify

```bash
# Listar todos los contenedores con sus nombres
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
```

Coolify suele nombrar los contenedores de una de estas formas:
- `mi-app` (si tú lo especificaste)
- `mi-app-randomsuffix` (nombre generado automáticamente)
- `coolify-mi-app-1` (en stacks multi-contenedor)

### Encontrar etiquetas de Coolify

```bash
# Ver las etiquetas de un contenedor específico
docker inspect nombre-del-contenedor | python3 -c "
import json, sys
data = json.load(sys.stdin)
labels = data[0]['Config']['Labels']
for k, v in sorted(labels.items()):
    print(f'{k}={v}')
"
```

Las etiquetas más útiles de Coolify son:
- `coolify.appId` – ID único de la aplicación en Coolify
- `coolify.name` – nombre legible de la aplicación
- `coolify.type` – tipo de despliegue
- `com.docker.compose.project` – nombre del stack

### Configuración recomendada para Coolify

Usa `container_label` para máxima resiliencia ante reinicios o redespligues:

```yaml
name: "mi-tienda-coolify"
type: wordpress
container_label: "coolify.appId=clxxxxxxxxxxxxxxxx"
app_root: /var/www/html
```

### Coolify en modo Swarm

Si usas Docker Swarm con Coolify, el nombre del servicio sigue el patrón `stack_service`. Usa el prefijo:

```yaml
container_name_prefix: "mi-stack-wordpress"
```

### Redes de Coolify

Coolify crea redes Docker con el nombre `coolify`. Para que CENTINELA pueda inspeccionar el tráfico de contenedores en esta red, añade la red al `docker-compose.yml`:

```yaml
services:
  centinela:
    networks:
      - default
      - coolify

networks:
  coolify:
    external: true
```

---

## 7. Cómo funcionan las alertas

### Tipos de alertas

| Tipo de incidente | Severidad | Descripción |
|---|---|---|
| `DOCKER_EVENT_EXEC` | Alta | Se ejecutó un comando dentro del contenedor |
| `DOCKER_EVENT_RESTART` | Media | El contenedor se reinició (posible crash) |
| `DOCKER_EVENT_STOP` | Media | El contenedor se detuvo inesperadamente |
| `PROCESS_SUSPICIOUS` | Alta | Se detectó un proceso de la lista negra |
| `NETWORK_SPIKE` | Media/Alta | Pico de tráfico superior al baseline |
| `NETWORK_NEW_DEST` | Media | Conexión a un destino no visto antes |
| `FILESYSTEM_CHANGE` | Alta | Cambio en una ruta crítica |
| `FILESYSTEM_PHP_UPLOAD` | Crítica | PHP subido al directorio de uploads |
| `SECURITY_AUDIT` | Variable | Resultado de la auditoría periódica |

### Flujo de una alerta

```
Evento detectado
      │
      ▼
¿Está el proyecto enabled?  ──No──▶  Ignorar
      │ Sí
      ▼
¿La severidad >= min_severity del proyecto?  ──No──▶  Log sin alerta
      │ Sí
      ▼
¿Hay cooldown activo para este tipo+contenedor?  ──Sí──▶  Suprimir alerta
      │ No
      ▼
Guardar incidente en BD
      │
      ▼
¿Es ventana de despliegue + incidente de filesystem?  ──Sí──▶  Log sin alerta
      │ No
      ▼
Enviar alertas en paralelo:
  ├── Email (SMTP)
  ├── Webhook HTTP (POST JSON)
  └── WhatsApp (bridge HTTP)
```

### Formato del payload de webhook

```json
{
  "incident_id": "uuid-v4",
  "timestamp": "2024-01-15T10:30:00Z",
  "project": "mi-wordpress-tienda",
  "container": "wordpress-tienda",
  "type": "FILESYSTEM_PHP_UPLOAD",
  "severity": "critical",
  "message": "PHP file uploaded to /var/www/html/wp-content/uploads/shell.php",
  "details": {
    "path": "/var/www/html/wp-content/uploads/shell.php",
    "event": "create",
    "inode": 123456
  }
}
```

### Configurar Slack

Crea un Incoming Webhook en Slack y ponlo en el fichero de proyecto:

```yaml
alerts:
  webhook_url: "https://hooks.slack.com/services/T.../B.../xxx"
```

### Configurar WhatsApp

CENTINELA soporta cualquier bridge HTTP que acepte un POST JSON. Ejemplos compatibles:
- [WA-Bridge](https://github.com/wa-bridge/wa-bridge)
- [Waha](https://waha.devlike.pro/)
- [Twilio WhatsApp API](https://www.twilio.com/whatsapp)

```yaml
alerts:
  whatsapp_webhook: "https://tu-bridge.com/api/send"
```

El payload enviado es el mismo JSON que para otros webhooks.

---

## 8. Gestión de la base de datos

### SQLite (por defecto)

La base de datos SQLite se guarda en `./data/centinela.db` en el host.

**Hacer una copia de seguridad:**
```bash
# Mientras CENTINELA está corriendo (SQLite soporta hot backup)
sqlite3 ./data/centinela.db ".backup ./data/centinela-backup-$(date +%Y%m%d).db"
```

**Ver los últimos incidentes:**
```bash
sqlite3 ./data/centinela.db \
  "SELECT timestamp, project, type, severity, message FROM incidents ORDER BY timestamp DESC LIMIT 20;"
```

**Ver incidentes de las últimas 24 horas:**
```bash
sqlite3 ./data/centinela.db \
  "SELECT * FROM incidents WHERE timestamp >= datetime('now', '-24 hours') ORDER BY timestamp DESC;"
```

**Exportar a CSV:**
```bash
sqlite3 -csv ./data/centinela.db \
  "SELECT * FROM incidents;" > incidentes-$(date +%Y%m%d).csv
```

**Limpiar incidentes antiguos (más de 90 días):**
```bash
sqlite3 ./data/centinela.db \
  "DELETE FROM incidents WHERE timestamp < datetime('now', '-90 days');"
```

### Migrar a PostgreSQL

Para entornos de producción con alto volumen de incidentes o acceso multi-usuario, PostgreSQL es la mejor opción.

**1. Instalar el driver:**
```bash
# Añadir a requirements.txt:
asyncpg>=0.29.0
```

**2. Actualizar centinela.yml:**
```yaml
storage:
  db_url: "postgresql+asyncpg://centinela:password@postgres-host:5432/centinela"
```

**3. Migrar los datos existentes de SQLite a PostgreSQL:**
```bash
# Exportar desde SQLite
sqlite3 ./data/centinela.db .dump > centinela_dump.sql

# Adaptar el SQL para PostgreSQL (cambios de sintaxis mínimos)
# y luego importar:
psql -h postgres-host -U centinela -d centinela < centinela_dump.sql
```

**4. Añadir PostgreSQL al docker-compose.yml:**
```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: centinela
      POSTGRES_USER: centinela
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  centinela:
    depends_on:
      - postgres

volumes:
  postgres_data:
```

### Rotación automática de la BD

Para evitar que la base de datos crezca indefinidamente, añade una tarea cron en el host:

```bash
# /etc/cron.weekly/centinela-cleanup
#!/bin/bash
sqlite3 /ruta/a/centinela/data/centinela.db \
  "DELETE FROM incidents WHERE timestamp < datetime('now', '-180 days');"
```

---

## 9. Archivos de log

Los logs de CENTINELA se escriben en `./logs/` en el host (montado en `/app/logs` dentro del contenedor).

### Ficheros de log generados

| Fichero | Contenido | Rotación |
|---|---|---|
| `centinela.log` | Log principal: todos los eventos del sistema | 10 MB, 5 ficheros |
| `incidents.log` | Solo incidentes de seguridad (JSON estructurado) | 10 MB, 10 ficheros |
| `alerts.log` | Historial de alertas enviadas y su estado | 5 MB, 5 ficheros |
| `docker_events.log` | Stream de eventos Docker crudos | 5 MB, 3 ficheros |
| `network_baseline.log` | Actualizaciones del baseline de red | 2 MB, 3 ficheros |
| `audit.log` | Resultados de auditorías de seguridad | 5 MB, 5 ficheros |

### Ver logs en tiempo real

```bash
# Log principal
tail -f logs/centinela.log

# Solo incidentes de seguridad
tail -f logs/incidents.log | python3 -m json.tool

# Seguir los logs del contenedor
docker compose logs -f centinela

# Filtrar por nivel de severidad
docker compose logs centinela 2>&1 | grep '\[ERROR\]\|\[CRITICAL\]'
```

### Formato del log de incidentes

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "WARNING",
  "incident_id": "a1b2c3d4-...",
  "project": "mi-wordpress-tienda",
  "container": "wordpress-tienda",
  "type": "PROCESS_SUSPICIOUS",
  "severity": "high",
  "message": "Suspicious process detected: /bin/bash (pid=1234)",
  "details": {
    "pid": 1234,
    "cmdline": "/bin/bash -c 'cat /etc/passwd'",
    "user": "www-data"
  }
}
```

### Cambiar el nivel de verbosidad

En el fichero `.env`:
```env
CENTINELA_LOG_LEVEL=DEBUG   # Ver todo, incluyendo eventos normales
CENTINELA_LOG_LEVEL=INFO    # Nivel normal de producción (por defecto)
CENTINELA_LOG_LEVEL=WARNING # Solo problemas y alertas
```

Aplica el cambio sin rebuild:
```bash
docker compose up -d
```

---

## 10. Solución de problemas

### CENTINELA no arranca

**Síntoma:** `docker compose logs centinela` muestra error de conexión a Docker.

```
CRITICAL centinela.main – Cannot connect to Docker daemon
```

**Solución:**
```bash
# Verificar que el socket de Docker existe
ls -la /var/run/docker.sock

# Verificar que el usuario tiene permisos
groups $USER | grep docker

# Si no está en el grupo docker:
sudo usermod -aG docker $USER
newgrp docker
```

---

**Síntoma:** Error al cargar la configuración.

```
ERROR centinela.config – Failed to parse centinela.yml
```

**Solución:**
```bash
# Validar la sintaxis YAML
python3 -c "import yaml; yaml.safe_load(open('config/centinela.yml'))" && echo "OK"

# Ver el error exacto
docker compose run --rm centinela python -c "
from config.loader import load_config
load_config('/app/config/centinela.yml')
print('Config OK')
"
```

---

### No llegan alertas por email

**1. Verificar la conectividad SMTP:**
```bash
docker compose exec centinela python3 -c "
import smtplib, ssl
ctx = ssl.create_default_context()
with smtplib.SMTP('smtp.gmail.com', 587) as s:
    s.ehlo()
    s.starttls(context=ctx)
    s.login('tu@gmail.com', 'contraseña-de-aplicación')
    print('SMTP OK')
"
```

**2. Verificar logs de alertas:**
```bash
grep -i 'email\|smtp\|alert' logs/centinela.log | tail -20
```

**3. Problemas comunes con Gmail:**
- Estás usando la contraseña de la cuenta en vez de una **contraseña de aplicación**.
- La verificación en 2 pasos no está activada (requerida para contraseñas de aplicación).
- El acceso a apps menos seguras está desactivado (usa contraseñas de aplicación en su lugar).

---

### Un contenedor no está siendo monitorizado

**Síntoma:** CENTINELA arranca pero no genera alertas para un contenedor específico.

**Diagnóstico:**
```bash
# Verificar que el contenedor está corriendo
docker ps | grep nombre-del-contenedor

# Verificar que CENTINELA lo ha detectado
docker compose logs centinela | grep "nombre-del-contenedor"

# Verificar el nombre exacto del contenedor
docker inspect nombre-del-contenedor --format '{{.Name}}'
# El nombre incluye una barra inicial: /nombre-del-contenedor
# En la config CENTINELA, NO incluyas la barra
```

**Solución más común:** El `container_name` en el fichero de proyecto no coincide exactamente con el nombre del contenedor Docker. Verifica con `docker ps --format "{{.Names}}"`.

---

### Demasiadas alertas (alert storm)

**Síntoma:** Recibes decenas de emails en pocos minutos.

**Solución:**

1. Aumenta los cooldowns en `centinela.yml`:
```yaml
alert_cooldown:
  FILESYSTEM_CHANGE: 1800   # 30 minutos entre alertas de filesystem
  PROCESS_SUSPICIOUS: 600   # 10 minutos entre alertas de proceso
```

2. Aumenta la severidad mínima en el fichero del proyecto:
```yaml
alerts:
  min_severity: high   # Solo alertas altas y críticas
```

3. Añade rutas problemáticas a `exclude_paths`:
```yaml
exclude_paths:
  - storage/framework/cache   # Se regenera constantemente
  - wp-content/cache
```

---

### Alertas de filesystem durante un despliegue legítimo

**Solución:** Define ventanas de despliegue en el fichero del proyecto:

```yaml
deployment_windows:
  - start: "02:00"
    end: "04:00"
    days:
      - monday
      - wednesday
      - friday
```

También puedes pausar temporalmente la monitorización de un proyecto:
```yaml
enabled: false
```

Y volver a activarla después:
```yaml
enabled: true
```

Sin necesidad de reiniciar CENTINELA (relee la configuración automáticamente).

---

### Uso elevado de CPU

**Síntoma:** CENTINELA consume más CPU de la esperada.

**Causas habituales y soluciones:**

1. **Intervalo de escaneo de procesos demasiado bajo:**
```yaml
monitoring:
  process_check_interval: 120   # Subir de 60 a 120 segundos
```

2. **Demasiados contenedores monitorizados simultáneamente:**
Considera usar `monitor_processes: false` en proyectos de baja prioridad.

3. **Eventos de filesystem de alta frecuencia:**
Revisa los logs para identificar qué ruta genera más eventos:
```bash
grep "FILESYSTEM" logs/incidents.log | \
  python3 -c "import json,sys; [print(json.loads(l)['details']['path']) for l in sys.stdin]" | \
  sort | uniq -c | sort -rn | head -20
```

---

## 11. Hardening de seguridad

### El paradox del centinela privilegiado

CENTINELA requiere privilegios elevados para hacer su trabajo (leer `/proc`, usar inotify en mounts del host). Esto significa que si CENTINELA es comprometido, el atacante tiene acceso privilegiado al host. Estas medidas minimizan ese riesgo.

### 1. Usar capabilities en vez de privileged

En vez de `privileged: true`, puedes conceder solo las capabilities necesarias:

```yaml
# En docker-compose.yml
services:
  centinela:
    # privileged: true   # ELIMINAR
    cap_drop:
      - ALL
    cap_add:
      - SYS_PTRACE       # Leer /proc de otros procesos
      - NET_ADMIN        # Inspeccionar interfaces de red
      - DAC_READ_SEARCH  # Leer ficheros sin permisos de lectura
    security_opt:
      - no-new-privileges:true
```

**Nota:** Algunas características de inotify sobre mounts pueden requerir `privileged: true`. Prueba con capabilities primero y usa `privileged` solo si es necesario.

### 2. Red de solo lectura

```yaml
services:
  centinela:
    read_only: true  # Sistema de ficheros raíz de solo lectura
    tmpfs:
      - /tmp         # Directorio temporal en memoria
```

### 3. Usuario no-root dentro del contenedor

Añade al Dockerfile:
```dockerfile
RUN groupadd -r centinela && useradd -r -g centinela centinela
RUN chown -R centinela:centinela /app
USER centinela
```

**Nota:** Algunas operaciones de monitorización pueden requerir root. Prueba con un usuario no-root y verifica que todas las funciones siguen operativas.

### 4. Secrets para credenciales SMTP

En vez de guardar la contraseña en texto plano en `centinela.yml`, usa Docker Secrets:

```yaml
# docker-compose.yml
services:
  centinela:
    secrets:
      - smtp_password
    environment:
      - SMTP_PASSWORD_FILE=/run/secrets/smtp_password

secrets:
  smtp_password:
    file: ./secrets/smtp_password.txt
```

Y en el código, lee el secreto desde el fichero.

### 5. Restringir el acceso al socket de Docker

El socket de Docker es equivalente a root en el host. Considera usar un proxy de solo lectura:

```yaml
# docker-compose.yml
services:
  centinela:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    # Añadir un proxy como Tecnativa/docker-socket-proxy
    # que filtre las operaciones permitidas
```

[Docker Socket Proxy](https://github.com/Tecnativa/docker-socket-proxy) te permite permitir solo las llamadas API que CENTINELA necesita (Events, Containers, Exec).

### 6. Monitorizar al monitor

Crea alertas externas que comprueben que CENTINELA sigue corriendo:

```bash
# Script de comprobación en el host (ejecutar desde cron cada 5 minutos)
#!/bin/bash
if ! docker ps --format '{{.Names}}' | grep -q 'centinela'; then
    echo "ALERTA: CENTINELA no está corriendo" | \
    mail -s "CENTINELA DOWN" admin@tudominio.com
fi
```

### 7. Auditar los logs de CENTINELA

Los propios logs de CENTINELA son una superficie de ataque potencial. Asegúrate de que:
- `./logs/` no es accesible públicamente
- Los logs se envían a un sistema de log centralizado (Loki, Elasticsearch) para detección de manipulación
- Se configuran alertas si CENTINELA deja de escribir logs (indica que ha sido detenido)

---

## 12. Hoja de ruta

### v1.1 – Mejoras de detección
- [ ] Integración con ClamAV para escaneo de ficheros subidos
- [ ] Análisis de logs de acceso de Nginx/Apache (detección de escáneres web, fuerza bruta)
- [ ] Reglas de YARA para detección de webshells conocidos
- [ ] Monitorización de cambios en base de datos WordPress (tablas `wp_options`, `wp_users`)

### v1.2 – Mejoras de alertas
- [ ] Interfaz web para revisar incidentes y gestionar configuración
- [ ] Integración nativa con Telegram (actualmente via webhook genérico)
- [ ] Agrupación de alertas relacionadas para reducir ruido
- [ ] Informe semanal automático por email con resumen de incidentes

### v1.3 – Análisis avanzado
- [ ] Detección de anomalías basada en ML (baseline de comportamiento con scikit-learn)
- [ ] Análisis de patrones de acceso de red (detección de C2 por frecuencia de beaconing)
- [ ] Correlación de eventos multi-contenedor (atacante pivotando entre servicios)
- [ ] Integración con feeds de threat intelligence (IPs maliciosas conocidas)

### v2.0 – Escala
- [ ] Soporte multi-host (agentes remotos con control centralizado)
- [ ] Dashboard Grafana con métricas en tiempo real via Prometheus
- [ ] API REST para integración con SIEMs (Splunk, Elastic SIEM, Wazuh)
- [ ] Soporte para Docker Swarm y Kubernetes (adaptadores de plataforma)
- [ ] Modo de respuesta activa (aislar contenedor comprometido automáticamente)

### Contribuir

CENTINELA es un proyecto en desarrollo activo. Las contribuciones son bienvenidas:

1. Haz fork del repositorio
2. Crea una rama para tu funcionalidad (`git checkout -b feature/nueva-deteccion`)
3. Añade tests para cualquier nueva funcionalidad
4. Asegúrate de que `make test` pasa
5. Envía un Pull Request con una descripción detallada

---

## Licencia

MIT License. Ver fichero `LICENSE` para más detalles.

---

*CENTINELA fue creado para proteger aplicaciones web en entornos Docker self-hosted. Si lo usas en producción, considera contribuir con tus reglas de detección de vuelta al proyecto.*
