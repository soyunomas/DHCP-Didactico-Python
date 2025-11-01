# src/dhcp_handler.py
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, get_if_hwaddr
from ipaddress import IPv4Address
from src.logger import DhcpLogger
import time
import threading
from enum import IntEnum

class DHCPMessageType(IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8

class DHCPHandler:
    CONVERSATION_COOLDOWN_SECONDS = 5

    def __init__(self, config, db, log_mode='profesional', lock=None):
        if not lock:
            raise ValueError("Se requiere un objeto Lock para el handler.")
        
        self.config = config
        self.db = db
        self.server_ip = config['server_ip']
        self.mac_map = {}
        self.conversation_counter = 0
        self.lock = lock
        self.logger = DhcpLogger(mode=log_mode, server_ip=self.server_ip, lock=self.lock)

        try:
            self.iface_mac = get_if_hwaddr(config['interface'])
        except Exception as e:
            print(f"[ERROR CRÍTICO] No se pudo obtener la MAC de la interfaz '{config['interface']}'. Error: {e}")
            exit(1)
        
        # --- LÍNEA REDUNDANTE ELIMINADA DE AQUÍ ---

    def _get_convo_id(self, mac):
        with self.lock:
            current_time = time.time()
            if mac in self.mac_map:
                convo_id, timestamp = self.mac_map[mac]
                if current_time - timestamp < self.CONVERSATION_COOLDOWN_SECONDS:
                    self.mac_map[mac] = (convo_id, current_time)
                    return convo_id
            
            self.conversation_counter += 1
            new_convo_id = f"Conversación #{self.conversation_counter}"
            self.mac_map[mac] = (new_convo_id, current_time)
            self.logger.log_new_conversation(mac, self.conversation_counter)
            return new_convo_id

    def _clear_convo_id(self, mac):
        with self.lock:
            if mac in self.mac_map:
                del self.mac_map[mac]

    def handle_packet(self, pkt):
        if not pkt.haslayer(Ether): return None

        src_mac = pkt[Ether].src
        
        if src_mac == self.iface_mac:
            return None
            
        if pkt.haslayer(UDP) and pkt[UDP].sport == 67:
            rogue_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            self.logger.log_rogue_server_detected(src_mac, rogue_ip)
            return None

        if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP): return None

        convo_id = self._get_convo_id(src_mac)
        msg_type_opt = next((opt for opt in pkt[DHCP].options if opt[0] == 'message-type'), None)
        if not msg_type_opt: return None
        
        msg_type = msg_type_opt[1]
        
        if msg_type == DHCPMessageType.DISCOVER:
            return self._handle_discover(pkt, convo_id)
        elif msg_type == DHCPMessageType.REQUEST:
            return self._handle_request(pkt, convo_id)
        elif msg_type == DHCPMessageType.RELEASE:
            lease = self.db.get_lease(src_mac)
            if lease:
                self.db.add_history_log(src_mac, lease['ip'], 'RELEASE')
                self.logger.log_db_history_update(src_mac, lease['ip'], 'RELEASE', convo_id)
            self.db.release_lease(src_mac)
            self.logger.log_release(src_mac, convo_id)
            self._clear_convo_id(src_mac)
            return None
        elif msg_type == DHCPMessageType.DECLINE:
            requested_ip_opt = next((opt for opt in pkt[DHCP].options if opt[0] == 'requested_addr'), None)
            declined_ip = requested_ip_opt[1] if requested_ip_opt else "N/A"
            self.db.release_lease(src_mac) 
            if declined_ip != "N/A":
                self.db.add_history_log(src_mac, declined_ip, 'DECLINE')
                self.logger.log_db_history_update(src_mac, declined_ip, 'DECLINE', convo_id)
            self.logger.log_decline(src_mac, declined_ip, convo_id)
            self._clear_convo_id(src_mac)
            return None
        
        return None

    def _craft_response_packet(self, request_pkt, yiaddr, dest_ip="255.255.255.255", dest_mac="ff:ff:ff:ff:ff:ff"):
        use_broadcast = request_pkt[BOOTP].flags & 0x8000
        ciaddr_is_set = request_pkt[BOOTP].ciaddr != '0.0.0.0'

        if not use_broadcast and ciaddr_is_set:
             dest_ip = request_pkt[BOOTP].ciaddr
             dest_mac = request_pkt[Ether].src

        if request_pkt[BOOTP].giaddr != '0.0.0.0':
            dest_ip = request_pkt[BOOTP].giaddr
            dest_mac = "ff:ff:ff:ff:ff:ff"

        return (
            Ether(src=self.iface_mac, dst=dest_mac) /
            IP(src=self.server_ip, dst=dest_ip) /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2, yiaddr=str(yiaddr), siaddr=self.server_ip, giaddr=request_pkt[BOOTP].giaddr,
                xid=request_pkt[BOOTP].xid, chaddr=request_pkt[BOOTP].chaddr, flags=request_pkt[BOOTP].flags
            )
        )

    def _handle_discover(self, pkt, convo_id):
        client_mac = pkt[Ether].src
        
        hostname_opt = next((opt for opt in pkt[DHCP].options if opt[0] == 'hostname'), None)
        hostname = hostname_opt[1].decode(errors='ignore') if hostname_opt else None

        if client_mac in self.config.get('blocked_macs', []):
            self.logger.log_blocked(client_mac, convo_id)
            self._clear_convo_id(client_mac)
            return None

        self.logger.log_discover(client_mac, hostname, convo_id)
        
        ip_to_offer = self.config['reservations'].get(client_mac)
        if not ip_to_offer:
            lease = self.db.get_lease(client_mac)
            ip_to_offer = lease['ip'] if lease else self.db.find_available_ip(
                self.config['subnet']['pool_start'], self.config['subnet']['pool_end'], self.config['reservations']
            )
        
        if not ip_to_offer:
            self.logger.log_no_ips_available(convo_id)
            self._clear_convo_id(client_mac)
            return None
            
        self.logger.log_offer(client_mac, ip_to_offer, convo_id)
        response_pkt = self._craft_response_packet(pkt, ip_to_offer)
        response_pkt /= DHCP(options=[("message-type", DHCPMessageType.OFFER), ("server_id", self.server_ip), ("lease_time", self.config['lease_time_seconds']), ("subnet_mask", self.config['subnet']['mask']), ("router", self.config['subnet']['gateway']), ("name_server", *self.config['dns_servers']), ("domain", self.config['domain_name'].encode()), "end"])
        return response_pkt

    def _handle_request(self, pkt, convo_id):
        client_mac = pkt[Ether].src
        client_ip_from_ciaddr = pkt[BOOTP].ciaddr
        
        hostname_opt = next((opt for opt in pkt[DHCP].options if opt[0] == 'hostname'), None)
        hostname = hostname_opt[1].decode(errors='ignore') if hostname_opt else None

        if client_ip_from_ciaddr != '0.0.0.0': # Proceso de renovación
            self.logger.log_renewal_request(client_mac, client_ip_from_ciaddr, convo_id)
            
            lease = self.db.get_lease(client_mac)
            if lease and lease['ip'] == client_ip_from_ciaddr:
                self.db.add_lease(client_mac, client_ip_from_ciaddr, self.config['lease_time_seconds'])
                self.db.add_history_log(client_mac, client_ip_from_ciaddr, 'RENEW')
                self.logger.log_db_history_update(client_mac, client_ip_from_ciaddr, 'RENEW', convo_id)
                self.logger.log_ack(client_mac, client_ip_from_ciaddr, convo_id, is_renewal=True)
                
                response_pkt = self._craft_response_packet(pkt, client_ip_from_ciaddr)
                response_pkt /= DHCP(options=[("message-type", DHCPMessageType.ACK), ("server_id", self.server_ip), ("lease_time", self.config['lease_time_seconds']), ("subnet_mask", self.config['subnet']['mask']), ("router", self.config['subnet']['gateway']), ("name_server", *self.config['dns_servers']), ("domain", self.config['domain_name'].encode()), "end"])
                self._clear_convo_id(client_mac)
                return response_pkt
            else:
                self.logger.log_nak(client_mac, client_ip_from_ciaddr, convo_id)
                self._clear_convo_id(client_mac)
                return self._handle_nak(pkt)
        
        else: # Proceso de asignación inicial (selección)
            requested_ip_opt = next((opt for opt in pkt[DHCP].options if opt[0] == 'requested_addr'), None)
            requested_ip = requested_ip_opt[1] if requested_ip_opt else None
            
            server_id_opt = next((opt for opt in pkt[DHCP].options if opt[0] == 'server_id'), None)
            server_id = server_id_opt[1] if server_id_opt else None
            
            is_for_other_server = server_id and server_id != self.server_ip
            is_valid = self._validate_requested_ip(client_mac, requested_ip)
            
            self.logger.log_request(client_mac, requested_ip, server_id, leads_to_nak=(not is_valid), is_for_other_server=is_for_other_server, hostname=hostname, convo_id=convo_id)
            
            if is_for_other_server:
                self.logger.log_request_ignored(convo_id)
                self._clear_convo_id(client_mac)
                return None
                
            if not is_valid:
                self.logger.log_nak(client_mac, requested_ip, convo_id)
                self._clear_convo_id(client_mac)
                return self._handle_nak(pkt)

            self.db.add_lease(client_mac, requested_ip, self.config['lease_time_seconds'])
            self.db.add_history_log(client_mac, requested_ip, 'ASSIGN')
            self.logger.log_db_history_update(client_mac, requested_ip, 'ASSIGN', convo_id)
            self.logger.log_ack(client_mac, requested_ip, convo_id, is_renewal=False)
            
            lease_info = self.db.get_lease(client_mac)
            if lease_info:
                self.logger.log_db_update(client_mac, requested_ip, time.ctime(lease_info['expires_at']), convo_id)

            response_pkt = self._craft_response_packet(pkt, requested_ip)
            response_pkt /= DHCP(options=[("message-type", DHCPMessageType.ACK), ("server_id", self.server_ip), ("lease_time", self.config['lease_time_seconds']), ("subnet_mask", self.config['subnet']['mask']), ("router", self.config['subnet']['gateway']), ("name_server", *self.config['dns_servers']), ("domain", self.config['domain_name'].encode()), "end"])
            self._clear_convo_id(client_mac)
            return response_pkt

    def _validate_requested_ip(self, mac, ip):
        if not ip or ip == '0.0.0.0': return False
        if self.config['reservations'].get(mac) == ip: return True
        
        active_leases = self.db.get_active_leases()
        if ip in active_leases and active_leases[ip] != mac:
            return False 
        
        try:
            pool_start = int(IPv4Address(self.config['subnet']['pool_start']))
            pool_end = int(IPv4Address(self.config['subnet']['pool_end']))
            req_ip_int = int(IPv4Address(ip))
        except ValueError: 
            return False
            
        if pool_start <= req_ip_int <= pool_end or ip in self.config['reservations'].values():
            return True
                
        return False
        
    def _handle_nak(self, pkt):
        response_pkt = self._craft_response_packet(pkt, '0.0.0.0')
        response_pkt /= DHCP(options=[("message-type", DHCPMessageType.NAK), ("server_id", self.server_ip), "end"])
        return response_pkt
