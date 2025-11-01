# src/logger.py
import threading

class DhcpLogger:
    def __init__(self, mode='profesional', server_ip=None, lock=None):
        self.mode = mode
        self.server_ip = server_ip
        self.lock = lock if lock else threading.Lock()
        if self.mode != 'profesional':
            print(f"--- Logger inicializado en modo: {self.mode} ---")


    def _get_prefix(self, convo_id):
        return f"[{convo_id}] " if convo_id else ""

    def _safe_print(self, message):
        with self.lock:
            print(message)

    def _log(self, speaker, message, convo_id):
        prefix = self._get_prefix(convo_id)
        indent = "  " if "Servidor" in speaker else ""
        formatted_speaker = f"{speaker}:".ljust(25)
        output = f"{prefix}{indent}{formatted_speaker} {message}"
        self._safe_print(output)

    def _separator(self):
        self._safe_print(f"{'-' * 70}")

    def log_discover(self, mac, hostname=None, convo_id=None):
        if self.mode == 'profesional': return
        client_id = f"{hostname} ({mac})" if hostname else mac
        messages = {
            'chat': ('💻 Cliente', f"¡Hola red 👋! Soy {client_id}, ¿alguien me da una IP?"),
            'docente': ('🎓 Cliente (Análisis)', f"El cliente inicia el proceso DORA emitiendo un DHCPDISCOVER (broadcast) para localizar servidores."),
            'colegas': ('👷‍♂️ Cliente', f"Ey, ¿alguien por ahí que me dé una IP? Soy {client_id}.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_offer(self, mac, ip, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('🌐 Servidor', f"¡Hola, {mac}! Tengo la {ip} libre, ¿te interesa?"),
            'docente': ('👨‍🏫 Servidor (Acción)', f"El servidor responde con un DHCPOFFER, proponiendo la IP {ip} y los parámetros de red."),
            'colegas': ('🔧 Servidor', f"Aquí estoy 👋. Tengo la {ip} libre, ¿te mola?")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_request(self, mac, ip, server_id, leads_to_nak, is_for_other_server, hostname=None, convo_id=None):
        if self.mode == 'profesional': return
        server_display = server_id if server_id else self.server_ip
        
        # Modo Chat
        chat_msg = f"¡Perfecto! Quiero la {ip} que me ofreciste."
        if is_for_other_server: 
            chat_msg = f"(Al servidor {server_display}) ¡Gracias por la oferta, la acepto! Solicito la IP {ip}."
        elif leads_to_nak: 
            chat_msg = f"Oye servidor, antes tenía la {ip}, ¿puedo seguir con esa?"
        
        # Modo Docente
        docente_msg = f"El cliente selecciona la oferta emitiendo un DHCPREQUEST para la IP {ip}."
        if leads_to_nak:
            docente_msg = f"El cliente intenta reutilizar una concesión anterior para la IP {ip} emitiendo un DHCPREQUEST."

        # Modo Colegas
        colegas_msg = "Perfecto, me quedo con esa."
        if is_for_other_server:
            colegas_msg = f"(Al otro server {server_display}) ¡Eh, tú! Me quedo con tu IP ({ip})."
        elif leads_to_nak:
            colegas_msg = f"Oye, antes tenía la {ip}, ¿sigue libre?"

        messages = {
            'chat': ('💻 Cliente', chat_msg),
            'docente': ('🎓 Cliente (Análisis)', docente_msg),
            'colegas': ('👷‍♂️ Cliente', colegas_msg)
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_renewal_request(self, mac, ip, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('💻 Cliente', f"Oye servidor, sigo aquí, ¿renovamos la {ip}?"),
            'docente': ('🎓 Cliente (Análisis)', f"El cliente inicia la renovación (T1) enviando un DHCPREQUEST (unicast) para extender su lease de {ip}."),
            'colegas': ('👷‍♂️ Cliente', f"Oye, sigo aquí. ¿Renovamos mi IP?")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_ack(self, mac, ip, convo_id=None, is_renewal=False):
        if self.mode == 'profesional': return
        
        if is_renewal:
            chat_msg = f"¡Por supuesto! Tu concesión para {ip} ha sido renovada."
            docente_msg = f"Renovación aprobada. El servidor envía un DHCPACK para extender el tiempo de concesión de {ip}."
            colegas_msg = f"Claro bro, te la extiendo 💪."
        else:
            chat_msg = f"Confirmado ✅, la IP {ip} es tuya. ¡Bienvenido a la red!"
            docente_msg = f"El servidor confirma la asignación con un DHCPACK. La IP {ip} queda oficialmente concedida a {mac}."
            colegas_msg = f"Hecho, la {ip} es tuya. ¡A disfrutarla! 😁"

        messages = { 'chat': ('🌐 Servidor', chat_msg), 'docente': ('👨‍🏫 Servidor (Acción)', docente_msg), 'colegas': ('🔧 Servidor', colegas_msg) }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_nak(self, mac, ip, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('🌐 Servidor', f"Negativo ❌, no puedes usar la IP {ip} en esta red. Debes empezar de cero."),
            'docente': ('👨‍🏫 Servidor (Acción)', f"El servidor rechaza la solicitud con un DHCPNAK, forzando al cliente a reiniciar el proceso desde DISCOVER."),
            'colegas': ('🔧 Servidor', f"Ni de coña, esa IP ({ip}) no te vale aquí. Pide una nueva.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_decline(self, mac, ip, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('💻 Cliente', f"¡Servidor, hay un problema! La IP {ip} que me diste ya la está usando otro 😤. La rechazo."),
            'docente': ('🎓 Cliente (Análisis)', f"El cliente detecta un conflicto de IP (vía ARP) con {ip} y notifica al servidor con un DHCPDECLINE."),
            'colegas': ('👷‍♂️ Cliente', f"¡Jefe! La IP {ip} que me diste ya está pillada 😠. Te la devuelvo.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        # No ponemos separador aquí, porque el log del histórico viene después

    def log_db_update(self, mac, ip, expires_at, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('⚙️ Sistema', f"Registro actualizado: {mac} tiene la IP {ip} hasta {expires_at}."),
            'docente': ('⚙️ Sistema (Registro)', f"Se escribe la concesión en la base de datos: MAC={mac}, IP={ip}."),
            'colegas': ('⚙️ Sistema (Log)', f"DB actualizada. {mac} -> {ip}. Fichado.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()
    
    def log_db_history_update(self, mac, ip, event_type, convo_id=None):
        if self.mode == 'profesional': return
        event_type_upper = event_type.upper()
        messages = {
            'chat': ('⚙️ Sistema', f"Guardando en el histórico: El cliente {mac} ha realizado un {event_type_upper} para la IP {ip}."),
            'docente': ('⚙️ Sistema (Auditoría)', f"Se registra el evento '{event_type_upper}' en el histórico para MAC {mac} e IP {ip}."),
            'colegas': ('⚙️ Sistema (Auditoría)', f"Evento '{event_type_upper}' de {mac} con {ip} guardado en el histórico.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_request_ignored(self, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('⚙️ Sistema', "Esa solicitud era para otro servidor, así que la ignoramos."),
            'docente': ('⚙️ Sistema (Análisis)', "El 'server_id' del REQUEST no coincide con el nuestro. Se ignora el paquete."),
            'colegas': ('⚙️ Sistema (Log)', "Ese marrón no es para nosotros. Pasando.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()
        
    def log_blocked(self, mac, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('⚙️ Sistema', f"La MAC {mac} está en la lista de bloqueo. Petición ignorada."),
            'docente': ('⚙️ Sistema (Seguridad)', f"La MAC {mac} coincide con una regla de bloqueo. Se descarta la petición."),
            'colegas': ('⚙️ Sistema (Log)', f"La MAC {mac} está en la lista negra. A la calle.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()
        
    def log_no_ips_available(self, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('⚙️ Sistema', "No quedan direcciones IP disponibles en el pool para ofrecer."),
            'docente': ('⚙️ Sistema (Alerta)', "El pool de direcciones está agotado. No se pueden generar nuevas ofertas."),
            'colegas': ('⚙️ Sistema (Log)', "¡Houston, tenemos un problema! Nos hemos quedado sin IPs.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_release(self, mac, convo_id=None):
        if self.mode == 'profesional': return
        messages = {
            'chat': ('💻 Cliente', f"Gracias por todo, dejo libre la IP que me asignaste."),
            'docente': ('🎓 Cliente (Análisis)', f"El cliente libera voluntariamente su concesión de IP enviando un DHCPRELEASE."),
            'colegas': ('👷‍♂️ Cliente', f"Me voy, te devuelvo la IP. ¡Gracias por todo! 👋")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_new_conversation(self, mac, convo_number):
        if self.mode == 'profesional': return
        convo_id = f"Conversación #{convo_number}"
        messages = {
            'chat': ('⚙️ Sistema', f"Asignando nuevo ID de conversación al cliente {mac}."),
            'docente': ('⚙️ Sistema (Contexto)', f"Iniciando seguimiento de una nueva transacción DHCP para el cliente {mac}."),
            'colegas': ('⚙️ Sistema (Log)', f"Nuevo ticket para el cliente {mac}.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_rogue_server_detected(self, rogue_mac, rogue_ip):
        messages = {
            'chat': ('🚨 ALERTA', f"¡Cuidado! Se ha detectado otro servidor DHCP ({rogue_ip}) en la red. Esto puede causar conflictos."),
            'docente': ('🛡️ SEGURIDAD', f"ALERTA: Detectado tráfico de un servidor DHCP no autorizado en {rogue_ip} ({rogue_mac})."),
            'colegas': ('🕵️‍♂️ OJO', f"¡Al loro! Hay otro DHCP server en {rogue_ip} ({rogue_mac}) metiendo ruido. A ver quién es."),
            'profesional': ('🚨 ALERTA DE SEGURIDAD', f"Detectado servidor DHCP no autorizado. IP: {rogue_ip}, MAC: {rogue_mac}.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, None)
        self._separator()
