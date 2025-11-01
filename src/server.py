# src/server.py
import json
import argparse
import threading
from scapy.all import sniff, sendp, conf, Ether, BOOTP, DHCP
from src.database import LeaseDatabase
from src.dhcp_handler import DHCPHandler

# Mapa para traducir el tipo de mensaje DHCP a un string legible
MSG_TYPE_MAP = {
    2: 'DHCPOFFER',
    5: 'DHCPACK',
    6: 'DHCPNAK'
}

def load_config(path='config/config.json'):
    with open(path, 'r') as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description="Servidor DHCP en Python con logging personalizable.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--modo-docente", action="store_true", help="Activa el logging explicativo para enseñar el protocolo.")
    group.add_argument("--modo-colegas", action="store_true", help="Activa el logging informal, como entre colegas.")
    group.add_argument("--modo-chat", action="store_true", help="Muestra el diálogo DHCP como una conversación de chat.")
    args = parser.parse_args()

    log_mode = 'profesional'
    if args.modo_docente: log_mode = 'docente'
    elif args.modo_colegas: log_mode = 'colegas'
    elif args.modo_chat: log_mode = 'chat'

    print("Iniciando servidor DHCP en Python...")
    
    config = load_config()
    print(f"Servidor IP: {config['server_ip']}, Escuchando en: {config['interface']}")

    lock = threading.RLock()
    
    db = LeaseDatabase(lock=lock)
    handler = DHCPHandler(config, db, log_mode, lock=lock)

    def packet_handler_thread(pkt):
        try:
            response = handler.handle_packet(pkt)
            if response:
                sendp(response, iface=config['interface'], verbose=0)
                if log_mode == 'profesional':
                    # --- MEJORA EN EL LOGGING PROFESIONAL ---
                    client_mac = response[Ether].dst
                    yiaddr = response[BOOTP].yiaddr
                    # El primer elemento de las opciones es siempre el message-type
                    msg_type_code = response[DHCP].options[0][1]
                    msg_type_str = MSG_TYPE_MAP.get(msg_type_code, f'UNKNOWN({msg_type_code})')
                    
                    print(f"[{msg_type_str}] Sent IP {yiaddr} to MAC {client_mac}")
                    # --- FIN DE LA MEJORA ---
        except Exception as e:
            print(f"\n--- [ERROR CRÍTICO EN UN HILO] ---")
            print(f"El procesamiento del paquete falló con una excepción no controlada.")
            print(f"Error: {e}")
            print(f"Paquete problemático: {pkt.summary()}")
            print(f"---------------------------------\n")

    def process_packet_threaded(pkt):
        thread = threading.Thread(target=packet_handler_thread, args=(pkt,))
        thread.start()

    conf.checkIPaddr = False
    dhcp_filter = "udp and (port 67 or port 68)"
    
    print("Servidor listo. Escuchando peticiones DHCP...")
    print("-" * 70)
    
    sniff(filter=dhcp_filter, prn=process_packet_threaded, iface=config['interface'], store=0)

if __name__ == "__main__":
    main()
