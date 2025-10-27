# src/logger.py
import threading

class DhcpLogger:
    def __init__(self, mode='profesional', server_ip=None, lock=None):
        self.mode = mode
        self.server_ip = server_ip
        self.lock = lock if lock else threading.Lock()
        if self.mode != 'chat':
            print(f"--- Logger inicializado en modo: {self.mode} ---")

    def _get_prefix(self, convo_id):
        return f"[{convo_id}] " if convo_id else ""

    def _safe_print(self, message):
        with self.lock:
            print(message)

    def _log(self, speaker, message, convo_id):
        prefix = self._get_prefix(convo_id)
        indent = "  " if "Servidor" in speaker else ""
        formatted_speaker = f"{speaker}:".ljust(16)
        output = f"{prefix}{indent}{formatted_speaker} {message}"
        self._safe_print(output)

    def _separator(self):
        self._safe_print(f"{'-' * 70}")

    # <<< MEJORA: Se añade el parámetro hostname.
    def log_discover(self, mac, hostname=None, convo_id=None):
        client_id = f"{hostname} ({mac})" if hostname else mac
        messages = {
            'chat': ('💻 Cliente', f"¡Hola a todos! Soy {client_id}. ¿Alguien tiene una dirección IP?"),
            'docente': ('🎓 Cliente', f"DHCPDISCOVER: Un cliente ({client_id}) emite un broadcast buscando servidores DHCP."),
            'colegas': ('👷‍♂️ Cliente', f"DISCOVER en la línea de {client_id}. Está pidiendo IP a gritos.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_offer(self, mac, ip, convo_id=None):
        messages = {
            'chat': ('🌐 Servidor', f"¡Hola, {mac}! Te ofrezco la dirección {ip}. Si te interesa, solicítala formalmente."),
            'docente': ('👨‍🏫 Servidor', f"DHCPOFFER: Respondemos a {mac} proponiendo la dirección IP {ip} para su uso."),
            'colegas': ('🔧 Servidor', f"OFFER para {mac}. Le guardamos la {ip}. A ver si la pilla.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    # <<< MEJORA: Se añade el parámetro hostname.
    def log_request(self, mac, ip, server_id, leads_to_nak, is_for_other_server, hostname=None, convo_id=None):
        server_display = server_id if server_id else self.server_ip
        client_id = f"{hostname} ({mac})" if hostname else mac
        
        chat_msg = ""
        if is_for_other_server: chat_msg = f"(Al servidor {server_display}) Gracias por la oferta, ¡la acepto! Solicito la IP {ip}."
        elif leads_to_nak: chat_msg = f"Vengo de otra red y ya tenía la IP {ip}. ¿Puedo seguir usándola aquí?"
        else: chat_msg = f"¡Servidor {server_display}, acepto tu oferta! Solicito formalmente la IP {ip}."

        messages = {
            'chat': ('💻 Cliente', chat_msg),
            'docente': ('🎓 Cliente', f"DHCPREQUEST: El cliente {client_id} responde, solicitando formalmente la IP {ip} del servidor {server_display}."),
            'colegas': ('👷‍♂️ Cliente', f"REQUEST de {client_id}. Quiere la {ip} de {server_display}. Se ha decidido.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_renewal_request(self, mac, ip, convo_id=None):
        messages = {
            'chat': ('💻 Cliente', f"Hola de nuevo. Mi concesión para {ip} va a caducar. ¿Puedo renovarla?"),
            'docente': ('🎓 Cliente', f"DHCPREQUEST (Renovación): El cliente {mac} quiere extender su concesión para {ip}."),
            'colegas': ('👷‍♂️ Cliente', f"El colega {mac} quiere renovar la {ip}. No quiere líos.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_ack(self, mac, ip, convo_id=None, is_renewal=False):
        chat_msg = f"¡Confirmado, {mac}! La dirección IP {ip} es tuya. ¡Bienvenido a la red!"
        docente_msg = f"DHCPACK: Trato hecho. La IP {ip} queda asignada oficialmente a {mac}."
        colegas_msg = f"ACK para {mac} con la {ip}. Concesión cerrada. A otra cosa."
        if is_renewal:
            chat_msg = f"¡Por supuesto, {mac}! Tu concesión para {ip} ha sido renovada."
            docente_msg = f"DHCPACK (Renovación): Se ha extendido con éxito la concesión de {ip} para {mac}."
            colegas_msg = f"ACK de renovación para {mac} con la {ip}. Todo en orden."
        messages = { 'chat': ('🌐 Servidor', chat_msg), 'docente': ('👨‍🏫 Servidor', docente_msg), 'colegas': ('🔧 Servidor', colegas_msg) }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)

    def log_nak(self, mac, ip, convo_id=None):
        messages = {
            'chat': ('🌐 Servidor', f"¡Lo siento, {mac}! La IP {ip} que pides no es válida. Debes iniciar el proceso de nuevo."),
            'docente': ('👨‍🏫 Servidor', f"DHCPNAK: Solicitud denegada. La IP {ip} no es válida para {mac} en este contexto."),
            'colegas': ('🔧 Servidor', f"NAK a {mac}. La IP {ip} que pide es una locura. Que empiece de nuevo.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    # <<< NUEVA FUNCIÓN: Para registrar los mensajes DHCPDECLINE.
    def log_decline(self, mac, ip, convo_id=None):
        messages = {
            'chat': ('💻 Cliente', f"¡Servidor, hay un problema! La IP {ip} que me diste ya la está usando alguien. La rechazo."),
            'docente': ('🎓 Cliente', f"DHCPDECLINE: El cliente {mac} detectó un conflicto con la IP {ip} y la ha rechazado."),
            'colegas': ('👷‍♂️ Cliente', f"DECLINE de {mac} por la IP {ip}. ¡Hay un lío en la red!")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_db_update(self, mac, ip, expires_at, convo_id=None):
        messages = {
            'chat': ('⚙️ Sistema', f"Registro actualizado: {mac} tiene la IP {ip} hasta {expires_at}."),
            'docente': ('⚙️ Sistema', f"Base de Datos: Se registra la concesión. MAC: {mac}, IP: {ip}."),
            'colegas': ('⚙️ Sistema', f"DB actualizada. {mac} -> {ip}. Que no se nos olvide.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_request_ignored(self, convo_id=None):
        messages = {
            'chat': ('⚙️ Sistema', "Esa solicitud era para otro servidor, así que la ignoramos."),
            'docente': ('⚙️ Sistema', "Análisis: El REQUEST no era para nuestro servidor_id. Se ignora el paquete."),
            'colegas': ('⚙️ Sistema', "Ese REQUEST no era para nosotros. Que se apañe el otro server.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()
        
    def log_blocked(self, mac, convo_id=None):
        messages = {
            'chat': ('⚙️ Sistema', f"La MAC {mac} está en la lista de bloqueo. Petición ignorada."),
            'docente': ('⚙️ Sistema', f"Seguridad: La MAC {mac} está bloqueada. Ignorando su petición."),
            'colegas': ('⚙️ Sistema', f"Ojo, la MAC {mac} está en la lista negra. Ignorando.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()
        
    def log_no_ips_available(self, convo_id=None):
        messages = {
            'chat': ('⚙️ Sistema', "No quedan direcciones IP disponibles en el pool para ofrecer."),
            'docente': ('⚙️ Sistema', "Alerta: El pool de direcciones IP está agotado. No se pueden dar nuevas concesiones."),
            'colegas': ('⚙️ Sistema', "¡Houston, tenemos un problema! Nos hemos quedado sin IPs en el pool.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_release(self, mac, convo_id=None):
        messages = {
            'chat': ('💻 Cliente', f"Ya no necesito la dirección IP. ¡Gracias por todo!"),
            'docente': ('🎓 Cliente', f"DHCPRELEASE: El cliente {mac} ha liberado su concesión de IP de forma voluntaria."),
            'colegas': ('👷‍♂️ Cliente', f"El cliente {mac} ha mandado un RELEASE. IP libre de nuevo.")
        }
        speaker, msg = messages[self.mode]
        self._log(speaker, msg, convo_id)
        self._separator()

    def log_new_conversation(self, mac, convo_number):
        convo_id = f"Conversación #{convo_number}"
        msg = f"Asignando nuevo ID de conversación al cliente {mac}."
        self._log('⚙️ Sistema', msg, convo_id)

    def log_rogue_server_detected(self, rogue_mac, rogue_ip):
        messages = {
            'chat': ('🚨 ALERTA', f"¡Cuidado! Se ha detectado otro servidor DHCP ({rogue_ip}) en la red. Esto puede causar conflictos."),
            'docente': ('🛡️ SEGURIDAD', f"ALERTA: Detectado tráfico de un servidor DHCP no autorizado en {rogue_ip} ({rogue_mac})."),
            'colegas': ('🕵️‍♂️ OJO', f"¡Al loro! Hay otro DHCP server en {rogue_ip} ({rogue_mac}) metiendo ruido. A ver quién es.")
        }
        speaker, msg = messages[self.mode]
        # Esta es una alerta importante, no necesita un ID de conversación
        self._log(speaker, msg, None)
        self._separator()
