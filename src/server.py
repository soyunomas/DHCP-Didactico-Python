# src/server.py
import json
import argparse
import threading # <-- Importante que esté aquí
from scapy.all import sniff, sendp, conf, Ether
from src.database import LeaseDatabase
from src.dhcp_handler import DHCPHandler

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

    # --- CAMBIO CLAVE Y DEFINITIVO AQUÍ ---
    # Usamos un RLock en lugar de un Lock para prevenir deadlocks.
    lock = threading.RLock()
    # --- FIN DEL CAMBIO ---
    
    db = LeaseDatabase(lock=lock)
    handler = DHCPHandler(config, db, log_mode, lock=lock)

    def packet_handler_thread(pkt):
        try:
            response = handler.handle_packet(pkt)
            if response:
                sendp(response, iface=config['interface'], verbose=0)
                if log_mode == 'profesional':
                    print(f"[SEND] Enviada respuesta a {response[Ether].dst}")
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
