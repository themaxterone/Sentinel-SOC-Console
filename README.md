# Sentinel SOC Console

Interfaz web local para las funciones de investigación de `gui-soc.py`: auditoría de inicios de sesión, usuarios de riesgo, consultas KQL en Sentinel y Defender XDR, búsqueda de reputación IP, exportación de informes y estado de las API keys.

## Inicio

Requiere Python 3.10 o posterior. Con Conda, crea un entorno aislado e instala las dependencias así:

```powershell
conda create -n gui-soc --override-channels -c conda-forge python=3.12 pip
conda activate gui-soc
python -m pip install -r requirements.txt
python gui-soc.py
```

Abre `http://127.0.0.1:5000` en el navegador. El servidor escucha solo en la interfaz local del equipo.

## Credenciales

Las claves de AbuseIPDB se configuran directamente en la lista `ABUSEIPDB_API_KEYS` de `soc_core.py`. Añade cada clave como una cadena entre comillas, separada por comas. `INTIGRITI_ACCESS_TOKEN` continúa leyéndose desde una variable de entorno:

```powershell
$env:INTIGRITI_ACCESS_TOKEN = "token"
python gui-soc.py
```

Las claves escritas en el código quedan en texto claro. No publiques ni compartas `soc_core.py` mientras contenga credenciales reales.

La autenticación de Microsoft se realiza interactivamente al iniciar una consulta. Las acciones de Graph, Azure Log Analytics y Defender XDR requieren permisos y acceso a los recursos correspondientes. El workspace Sentinel puede configurarse desde la interfaz o descubrirse con la cuenta autenticada.

## Módulos

- **Auditoría de accesos:** consulta individual o masiva de UPN/SID, traducción SID y enriquecimiento AbuseIPDB; contempla el fallback a Sentinel cuando Graph aplica rate limit.
- **Usuarios de riesgo:** escaneo por nivel y antigüedad, seguido de auditoría de inicios de sesión de las cuentas detectadas.
- **Sentinel / XDR:** descubrimiento de workspaces y ejecución de KQL en Sentinel o Defender XDR, con enriquecimiento opcional de IPs.
- **Inteligencia de IP:** consulta individual, archivo de IPs o búsqueda semanal PaloAlto IPS; conserva filtros Intigriti y exportaciones HTML, CSV y blocklist.
- **Estado de API keys:** comprobación paralela de cuotas AbuseIPDB con claves enmascaradas.

Los informes se guardan en `signInsLogs`, `sentinelLogs` y `abuseIpLogs`. El tema claro/oscuro se recuerda en el navegador.
