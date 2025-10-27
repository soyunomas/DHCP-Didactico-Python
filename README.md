# DHCP-Didactico-Python

![Python Version](https://img.shields.io/badge/Python-3.7+-blue.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Un servidor DHCP funcional implementado en Python puro y Scapy, diseñado desde cero con un fuerte enfoque didáctico para enseñar el funcionamiento del protocolo.

Este proyecto nace de la necesidad de visualizar y desmitificar las comunicaciones que ocurren en una red cuando un dispositivo solicita una dirección IP. En lugar de ser una "caja negra", este servidor narra cada paso del proceso de una forma fácil de entender.

## ✨ Características Principales

*   **Implementación Completa del Flujo DORA:** Manejo del ciclo completo `Discover`, `Offer`, `Request` y `Ack`.
*   **Gestión Avanzada de Concesiones:** Soporte para renovaciones, liberaciones (`DHCPRELEASE`), denegaciones (`DHCPNAK`) y gestión de conflictos (`DHCPDECLINE`).
*   **Múltiples Modos de Logging:** La característica estrella del proyecto. Elige entre diferentes "narradores" para entender la conversación:
    *   **`--modo-docente`**: Explicaciones formales y técnicas de cada paso del protocolo.
    *   **`--modo-colegas`**: Una jerga técnica e informal, como si lo hablaras con un compañero de redes.
    *   **`--modo-chat`**: Visualiza la asignación de IP como una conversación de chat entre el cliente y el servidor.
*   **Configuración Centralizada:** Toda la configuración del servidor (pool de IPs, reservas estáticas, DNS, etc.) se gestiona desde un único archivo `config.json`.
*   **Base de Datos Persistente:** Utiliza SQLite para guardar y gestionar el estado de las concesiones de IP de forma concurrente y segura.
*   **Soporte para DHCP Relay:** El servidor es compatible con el campo `giaddr`, permitiendo su funcionamiento en redes más complejas con múltiples VLANs (requiere un agente de retransmisión configurado en el router).

## 🚀 Demostración de los Modos de Logging

Esta es la magia del proyecto. Observa cómo se narra la misma conversación DHCP de tres formas distintas:

### `--modo-docente` (Explicativo)
```text
--- Logger inicializado en modo: docente ---
Servidor listo. Escuchando peticiones DHCP...
----------------------------------------------------------------------
[Conversación #1] ⚙️ Sistema:        Asignando nuevo ID de conversación al cliente 0a:1b:2c:3d:4e:5f.
[Conversación #1] 🎓 Cliente:        DHCPDISCOVER: Un cliente (Mi-PC (0a:1b:2c:3d:4e:5f)) emite un broadcast buscando servidores DHCP.
[Conversación #1]   👨‍🏫 Servidor:      DHCPOFFER: Respondemos a 0a:1b:2c:3d:4e:5f proponiendo la dirección IP 192.168.1.100 para su uso.
----------------------------------------------------------------------
[Conversación #1] 🎓 Cliente:        DHCPREQUEST: El cliente Mi-PC (0a:1b:2c:3d:4e:5f) responde, solicitando formalmente la IP 192.168.1.100 del servidor 192.168.1.1.
[Conversación #1]   👨‍🏫 Servidor:      DHCPACK: Trato hecho. La IP 192.168.1.100 queda asignada oficialmente a 0a:1b:2c:3d:4e:5f.
[Conversación #1] ⚙️ Sistema:        Base de Datos: Se registra la concesión. MAC: 0a:1b:2c:3d:4e:5f, IP: 192.168.1.100.
----------------------------------------------------------------------
```

### `--modo-colegas` (Informal)
```text
--- Logger inicializado en modo: colegas ---
Servidor listo. Escuchando peticiones DHCP...
----------------------------------------------------------------------
[Conversación #1] ⚙️ Sistema:        Asignando nuevo ID de conversación al cliente 0a:1b:2c:3d:4e:5f.
[Conversación #1] 👷‍♂️ Cliente:       DISCOVER en la línea de Mi-PC (0a:1b:2c:3d:4e:5f). Está pidiendo IP a gritos.
[Conversación #1]   🔧 Servidor:      OFFER para 0a:1b:2c:3d:4e:5f. Le guardamos la 192.168.1.100. A ver si la pilla.
----------------------------------------------------------------------
[Conversación #1] 👷‍♂️ Cliente:       REQUEST de Mi-PC (0a:1b:2c:3d:4e:5f). Quiere la 192.168.1.100 de 192.168.1.1. Se ha decidido.
[Conversación #1]   🔧 Servidor:      ACK para 0a:1b:2c:3d:4e:5f con la 192.168.1.100. Concesión cerrada. A otra cosa.
[Conversación #1] ⚙️ Sistema:        DB actualizada. 0a:1b:2c:3d:4e:5f -> 192.168.1.100. Que no se nos olvide.
----------------------------------------------------------------------
```

### `--modo-chat` (Conversacional)
```text
--- Logger inicializado en modo: chat ---
Servidor listo. Escuchando peticiones DHCP...
----------------------------------------------------------------------
[Conversación #1] ⚙️ Sistema:        Asignando nuevo ID de conversación al cliente 0a:1b:2c:3d:4e:5f.
[Conversación #1] 💻 Cliente:        ¡Hola a todos! Soy Mi-PC (0a:1b:2c:3d:4e:5f). ¿Alguien tiene una dirección IP?
[Conversación #1]   🌐 Servidor:      ¡Hola, 0a:1b:2c:3d:4e:5f! Te ofrezco la dirección 192.168.1.100. Si te interesa, solicítala formalmente.
----------------------------------------------------------------------
[Conversación #1] 💻 Cliente:        ¡Servidor 192.168.1.1, acepto tu oferta! Solicito formalmente la IP 192.168.1.100.
[Conversación #1]   🌐 Servidor:      ¡Confirmado, 0a:1b:2c:3d:4e:5f! La dirección IP 192.168.1.100 es tuya. ¡Bienvenido a la red!
[Conversación #1] ⚙️ Sistema:        Registro actualizado: 0a:1b:2c:3d:4e:5f tiene la IP 192.168.1.100 hasta Tue Oct 28 02:07:00 2025.
----------------------------------------------------------------------
```

## 🏗️ Estructura del Proyecto
```
DHCP-Didactico-Python/
├── config/
│   └── config.json         # Archivo de configuración principal
├── data/
│   └── dhcp_leases.db      # Base de datos SQLite de concesiones
├── src/
│   ├── __init__.py
│   ├── database.py         # Módulo de gestión de la base de datos
│   ├── dhcp_handler.py     # Lógica principal del protocolo DHCP
│   ├── logger.py           # Módulo de logging con los modos didácticos
│   └── server.py           # Punto de entrada principal y sniffer de red
├── requirements.txt        # Dependencias del proyecto
└── README.md               # Este archivo
```

## 🔧 Instalación y Uso

### Prerrequisitos
*   Python 3.7 o superior
*   `pip` (gestor de paquetes de Python)

### Pasos

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/soyunomas/DHCP-Didactico-Python.git
    cd DHCP-Didactico-Python
    ```

2.  **Crea un entorno virtual (recomendado) e instala las dependencias:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # En Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Configura el servidor:**
    Abre el archivo `config/config.json` y ajústalo a tu red. Presta especial atención a:
    *   `server_ip`: La IP que tendrá este servidor DHCP. Debe ser una IP estática.
    *   `interface`: El nombre de la interfaz de red donde el servidor escuchará peticiones (ej. `eth0`, `eno1`, `enp3s0`). Puedes encontrarla con `ip a` o `ifconfig`.
    *   `subnet`: Define el rango de IPs (`pool_start`, `pool_end`) que el servidor podrá asignar.

4.  **Ejecuta el servidor:**
    El servidor necesita privilegios de administrador para escuchar en los puertos DHCP (67/68) y enviar paquetes a bajo nivel.

    *   **Modo por defecto (profesional/silencioso):**
        ```bash
        sudo python3 src/server.py
        ```

    *   **Con un modo de logging específico:**
        ```bash
        sudo python3 src/server.py --modo-docente
        # O
        sudo python3 src/server.py --modo-colegas
        # O
        sudo python3 src/server.py --modo-chat
        ```
    ¡Ahora, conecta un nuevo dispositivo a la red o reinicia la interfaz de red de un cliente para ver la magia en acción!

## 💡 Cómo Funciona

*   **`server.py`**: Es el punto de entrada. Utiliza **Scapy** para `sniff` (capturar) el tráfico DHCP en la interfaz especificada. Cada paquete capturado se procesa en un hilo separado para manejar múltiples clientes simultáneamente.
*   **`dhcp_handler.py`**: Es el cerebro. Analiza los paquetes DHCP entrantes, determina el tipo de mensaje y decide la acción a tomar (ofrecer una IP, confirmar una solicitud, etc.). Aquí se construye el paquete de respuesta, también con Scapy.
*   **`database.py`**: Es la memoria. Gestiona la base de datos SQLite donde se almacenan las concesiones de IP para asegurar que no se asigna la misma IP a dos clientes y para recordar las asignaciones existentes.
*   **`logger.py`**: Es el narrador. Proporciona el formato de salida según el modo elegido, haciendo que el proceso sea fácil de seguir y entender.

## ✅ Hoja de Ruta (To-Do)

Este es el estado actual de la implementación del protocolo y las futuras mejoras planeadas. 

### Funcionalidades Implementadas

-   [x] **Núcleo del Protocolo DHCP (RFC 2131)**
    -   [x] Procesamiento del flujo `DHCPDISCOVER` -> `DHCPOFFER`.
    -   [x] Procesamiento del flujo `DHCPREQUEST` -> `DHCPACK`.
    -   [x] Manejo de `DHCPNAK` para peticiones inválidas.
    -   [x] Manejo de `DHCPRELEASE` para liberación voluntaria de IP.
    -   [x] Manejo de `DHCPDECLINE` para la detección de conflictos de IP.
-   [x] **Gestión de Concesiones**
    -   [x] Base de datos persistente (SQLite) para el estado de las concesiones.
    -   [x] Renovación de concesiones existentes.
    -   [x] Soporte para reservas de IP estáticas por dirección MAC.
    -   [x] Búsqueda de la primera IP disponible en el pool definido.
-   [x] **Opciones DHCP (RFC 2132)**
    -   [x] **Envío:** Máscara de subred (1), Router (3), Servidores DNS (6), Nombre de Dominio (15), Tiempo de Concesión (51), ID del Servidor (54).
    -   [x] **Recepción:** Lectura de la IP Solicitada (50) y Nombre de Host (12) del cliente.
-   [x] **Arquitectura y Red**
    -   [x] Procesamiento concurrente de clientes usando hilos.
    -   [x] Compatibilidad con Agentes de Retransmisión (DHCP Relay) mediante el campo `giaddr`.
    -   [x] Detección de otros servidores DHCP en la red (Servidores "Rogue").

### Mejoras Futuras y Características Planeadas

-   [ ] **Soporte para más Mensajes DHCP**
    -   [ ] Implementar el manejo de `DHCPINFORM` para clientes con IP estática que solicitan opciones.
-   [ ] **Lógica de Múltiples Pools**
    -   [ ] Modificar `config.json` y la lógica del servidor para soportar múltiples subredes/pools.
    -   [ ] Asignar IPs de un pool específico basándose en el `giaddr` de la petición.
-   [ ] **Soporte Avanzado para Opciones DHCP**
    -   [ ] **Opción 82 (Relay Agent Information):** Analizar esta opción para aplicar políticas de seguridad o asignación granular.
    -   [ ] **Opción 60 (Vendor Class Identifier):** Implementar lógica para ofrecer opciones personalizadas según el tipo de dispositivo (ej. teléfonos IP, impresoras).
    -   [ ] **Opción 66/67 (TFTP Server/Bootfile):** Añadir soporte para entornos de arranque en red (PXE).
    -   [ ] **Opción 42 (NTP Servers):** Permitir la configuración de servidores de tiempo.
-   [ ] **Mejoras en la Base de Datos**
    -   [ ] Crear una tabla o mecanismo para registrar y gestionar IPs en conflicto detectadas vía `DHCPDECLINE`.
    -   [ ] Añadir logging de eventos importantes a la base de datos.
-   [ ] **Mejoras Generales**
    -   [ ] Añadir pruebas unitarias para validar la lógica del `dhcp_handler`.
    -   [ ] Crear un archivo de log para registrar eventos de forma persistente, además de la salida en consola.

---



## 📄 Licencia

Este proyecto está distribuido bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
