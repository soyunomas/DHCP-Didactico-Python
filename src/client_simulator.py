# DHCP-Didactico-Python-main/client_simulator.py
import argparse
import random
import sys
import time
import threading
from scapy.all import (
    BOOTP,
    DHCP,
    IP,
    UDP,
    Ether,
    ARP,
    conf,
    srp,
    sendp,
    sniff,
    get_if_hwaddr,
    getmacbyip
)

# Intentamos importar 'rich', si no está, damos instrucciones claras.
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Error: La librería 'rich' no está instalada.")
    print("Por favor, instálala para usar este simulador: pip install rich")
    sys.exit(1)

# --- Constantes y Configuración ---
CLIENT_PORT = 68
SERVER_PORT = 67
HOSTNAME = "Mi-PC-Simulada"

# Generamos una MAC ficticia localmente administrada
FAKE_MAC = f"02:00:00:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"


class DHCPClientSimulator:
    """
    Un cliente DHCP simulado para interactuar con el servidor didáctico.
    Maneja su propio estado (IP, lease, etc.) y construye/envía paquetes.
    """

    def __init__(self, interface: str, console: Console):
        self.interface = interface
        self.console = console
        self.mac = FAKE_MAC
        self.xid = 0
        self.reset_state()
        conf.checkIPaddr = False
        self._stop_arp_listener = threading.Event()

    def reset_state(self):
        """Resetea el estado del cliente a sus valores iniciales."""
        self.current_ip = None
        self.server_ip = None
        self.server_mac = None
        self.subnet_mask = None
        self.router = None
        self.dns_servers = []
        self.domain_name = None
        self.broadcast_address = None
        self.lease_time = 0
        self.renewal_time = 0
        self.rebinding_time = 0
        self.lease_start_time = 0
        self.xid = random.randint(0, 0xFFFFFFFF)

    def _arp_responder(self):
        """
        Escucha peticiones ARP y responde si alguien pregunta por nuestra IP.
        """
        bpf_filter = f"arp[6:2] = 1 and ether dst ff:ff:ff:ff:ff:ff"
        self.console.print("[dim].. Hilo ARP listener iniciado ..[/dim]")
        
        def handle_arp_packet(pkt):
            if ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].pdst == self.current_ip:
                self.console.print(f"[bold blue]ARP request detectado: ¿Quién tiene {self.current_ip}? De {pkt[ARP].psrc}[/bold blue]")
                
                arp_reply = Ether(src=self.mac, dst=pkt[ARP].hwsrc) / \
                            ARP(op=2, pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc, psrc=self.current_ip, hwsrc=self.mac)
                
                sendp(arp_reply, iface=self.interface, verbose=0)
                self.console.print(f"[bold blue].. Enviando respuesta ARP: {self.current_ip} está en {self.mac} ..[/bold blue]")

        sniff(filter=bpf_filter, prn=handle_arp_packet, stop_filter=lambda p: self._stop_arp_listener.is_set(), iface=self.interface)
        self.console.print("[dim].. Hilo ARP listener detenido ..[/dim]")

    def _print_packet(self, title: str, packet, color: str = "cyan"):
        self.console.print(f"[{color} bold]TRANSMITIENDO -> {title}[/{color} bold]")
        self.console.print(packet.summary())
        if packet.haslayer(DHCP):
            self.console.print(f"  └─ DHCP Options: {packet[DHCP].options}")

    def _send_and_receive(self, packet_to_send, timeout: int = 5):
        bpf_filter = f"udp and src port {SERVER_PORT} and dst port {CLIENT_PORT}"
        self.console.print(f"[dim]Esperando respuesta (filtro BPF: '{bpf_filter}')...[/dim]")
        try:
            ans, _ = srp(
                packet_to_send, iface=self.interface, timeout=timeout, filter=bpf_filter, verbose=0
            )
            if ans:
                for sent, received in ans:
                    if received.haslayer(BOOTP) and received[BOOTP].xid == sent[BOOTP].xid:
                        return received
        except Exception as e:
            self.console.print(f"[bold red]Error durante el envío/recepción de paquetes: {e}[/bold red]")
        return None

    def _resolve_server_mac(self) -> str:
        if self.server_mac: return self.server_mac
        self.console.print(f"[dim]MAC del servidor no cacheada, intentando resolver para {self.server_ip} vía ARP...[/dim]")
        try:
            mac = getmacbyip(self.server_ip)
            if mac:
                self.console.print(f"[green]MAC del servidor resuelta: {mac}[/green]")
                self.server_mac = mac
                return mac
        except Exception as e:
            self.console.print(f"[bold red]Error durante la resolución ARP: {e}[/bold red]")
        self.console.print("[bold yellow]Advertencia: No se pudo resolver la MAC. Usando broadcast L2.[/bold yellow]")
        return "ff:ff:ff:ff:ff:ff"

    def run_discover(self):
        self.console.rule("[bold yellow]Iniciando Fase DISCOVER[/bold yellow]")
        self.reset_state() # Un discover siempre empieza de cero
        discover_pkt = (Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=CLIENT_PORT, dport=SERVER_PORT)/BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), flags=0x8000)/DHCP(options=[("message-type", "discover"), ("hostname", HOSTNAME.encode()), "end"]))
        self.xid = discover_pkt[BOOTP].xid
        self._print_packet("DHCP DISCOVER", discover_pkt)
        offer_pkt = self._send_and_receive(discover_pkt)
        if not offer_pkt or not offer_pkt.haslayer(DHCP) or ("message-type", 2) not in offer_pkt[DHCP].options:
            self.console.print("[bold red]❌ No se recibió una oferta (DHCPOFFER) válida.[/bold red]")
            return False
        self._print_packet("DHCPOFFER Recibido", offer_pkt, "green")
        self.server_mac = offer_pkt[Ether].src
        self.console.print(f"[bold dim]MAC del servidor detectada y guardada: {self.server_mac}[/bold dim]")
        self.current_ip = offer_pkt[BOOTP].yiaddr
        for opt in offer_pkt[DHCP].options:
            if not isinstance(opt, tuple): continue
            opt_name, opt_value = opt
            if opt_name == "server_id": self.server_ip = opt_value
            elif opt_name == "subnet_mask": self.subnet_mask = opt_value
            elif opt_name == "router": self.router = opt_value
            elif opt_name == "name_server": self.dns_servers = opt_value if isinstance(opt_value, list) else [opt_value]
            elif opt_name == "lease_time": self.lease_time = opt_value
            elif opt_name == "renewal_time": self.renewal_time = opt_value
            elif opt_name == "rebinding_time": self.rebinding_time = opt_value
            elif opt_name == "domain": self.domain_name = opt_value.decode('utf-8', errors='ignore')
            elif opt_name == "broadcast_address": self.broadcast_address = opt_value
        self.console.print(f"[bold green]✅ Oferta recibida: IP {self.current_ip} del servidor {self.server_ip}[/bold green]")
        return True

    def run_request(self):
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No se puede hacer un REQUEST sin una oferta previa.[/bold red]")
            return False
        self.console.rule("[bold yellow]Iniciando Fase REQUEST[/bold yellow]")
        request_pkt = (Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=CLIENT_PORT, dport=SERVER_PORT)/BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid, flags=0x8000)/DHCP(options=[("message-type", "request"), ("requested_addr", self.current_ip), ("server_id", self.server_ip), ("hostname", HOSTNAME.encode()), "end"]))
        self._print_packet("DHCP REQUEST", request_pkt)
        ack_pkt = self._send_and_receive(request_pkt)
        if not ack_pkt or not ack_pkt.haslayer(DHCP):
            self.console.print("[bold red]❌ No se recibió respuesta al REQUEST.[/bold red]")
            return False
        if ack_pkt[BOOTP].xid != self.xid:
            self.console.print("[bold red]❌ ID de transacción incorrecto. Ignorando.[/bold red]")
            return False
        msg_type = next((opt[1] for opt in ack_pkt[DHCP].options if opt[0] == 'message-type'), None)
        if msg_type == 5: # DHCPACK
            self._print_packet("DHCPACK Recibido", ack_pkt, "green")
            self.lease_start_time = time.time()
            self.console.print(f"[bold green]🎉 ¡CONCESIÓN CONFIRMADA! IP: {self.current_ip}[/bold green]")
            for opt in ack_pkt[DHCP].options:
                if not isinstance(opt, tuple): continue
                opt_name, opt_value = opt
                if opt_name == "lease_time": self.lease_time = opt_value
                elif opt_name == "renewal_time": self.renewal_time = opt_value
                elif opt_name == "rebinding_time": self.rebinding_time = opt_value
            return True
        elif msg_type == 6: # DHCPNAK
            self._print_packet("DHCPNAK Recibido", ack_pkt, "red")
            self.console.print("[bold red]❌ El servidor rechazó la solicitud (DHCPNAK).[/bold red]")
            self.reset_state()
            return False
        self.console.print(f"[bold red]❌ Respuesta DHCP desconocida (tipo: {msg_type}).[/bold red]")
        return False

    def run_renew(self):
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No hay una concesión activa para renovar.[/bold red]")
            return False
        
        self.console.rule("[bold yellow]Iniciando Renovación de Concesión[/bold yellow]")
        
        self._stop_arp_listener.clear()
        arp_thread = threading.Thread(target=self._arp_responder)
        arp_thread.start()
        time.sleep(0.1)
        
        success = False
        try:
            dest_mac = self._resolve_server_mac()
            renew_pkt = (Ether(src=self.mac, dst=dest_mac)/IP(src=self.current_ip, dst=self.server_ip)/UDP(sport=CLIENT_PORT, dport=SERVER_PORT)/BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid)/DHCP(options=[("message-type", "request"), "end"]))
            self._print_packet("DHCP RENEWAL REQUEST", renew_pkt)
            ack_pkt = self._send_and_receive(renew_pkt)
            
            if ack_pkt and ack_pkt.haslayer(DHCP) and ("message-type", 5) in ack_pkt[DHCP].options:
                self._print_packet("DHCPACK de Renovación Recibido", ack_pkt, "green")
                self.lease_start_time = time.time()
                self.console.print(f"[bold green]✅ Concesión para {self.current_ip} renovada con éxito.[/bold green]")
                success = True
            else:
                self.console.print("[bold red]❌ Falló la renovación de la concesión.[/bold red]")
        finally:
            self._stop_arp_listener.set()
            sendp(Ether(dst=self.mac)/IP(dst=self.current_ip)/UDP(dport=12345), iface=self.interface, verbose=0)
            arp_thread.join(timeout=1)
        
        return success

    def run_release(self):
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No hay una concesión activa para liberar.[/bold red]")
            return
        self.console.rule("[bold yellow]Iniciando Liberación de Concesión[/bold yellow]")
        dest_mac = self._resolve_server_mac()
        release_pkt = (Ether(src=self.mac, dst=dest_mac)/IP(src=self.current_ip, dst=self.server_ip)/UDP(sport=CLIENT_PORT, dport=SERVER_PORT)/BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid)/DHCP(options=[("message-type", "release"), ("server_id", self.server_ip), "end"]))
        self._print_packet("DHCP RELEASE", release_pkt)
        srp(release_pkt, iface=self.interface, timeout=1, verbose=0)
        self.console.print(f"[bold green]✅ IP {self.current_ip} liberada. Estado reseteado.[/bold green]")
        self.reset_state()

    def run_decline(self):
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No hay una concesión que rechazar.[/bold red]")
            return
        self.console.rule("[bold red]Iniciando Rechazo de Concesión (DECLINE)[/bold red]")
        decline_pkt = (Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=CLIENT_PORT, dport=SERVER_PORT)/BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid)/DHCP(options=[("message-type", "decline"), ("requested_addr", self.current_ip), ("server_id", self.server_ip), "end"]))
        self._print_packet("DHCP DECLINE", decline_pkt, "magenta")
        srp(decline_pkt, iface=self.interface, timeout=1, verbose=0)
        self.console.print(f"[bold green]✅ Conflicto por la IP {self.current_ip} notificado. Estado reseteado.[/bold green]")
        self.reset_state()
        
    def show_status(self):
        table = Table(title="[bold red]Estado Actual del Cliente DHCP Simulado[/bold red]")
        table.add_column("Parámetro", style="cyan")
        table.add_column("Valor")
        
        table.add_row("MAC Ficticia", self.mac)
        table.add_row("Hostname", HOSTNAME)
        table.add_row("---", "---")

        # --- MEJORA: Lógica para diferenciar entre oferta y concesión confirmada ---
        if self.current_ip:
            if self.lease_start_time > 0:
                ip_display = f"[bold green]{self.current_ip} (Confirmada)[/bold green]"
                lease_status = f"[green]Activa[/green]"
            else:
                ip_display = f"[yellow]{self.current_ip} (Oferta recibida)[/yellow]"
                lease_status = f"[yellow]Pendiente de confirmación[/yellow]"
        else:
            ip_display = "[dim]Ninguna[/dim]"
            lease_status = "[dim]N/A[/dim]"
        
        table.add_row("Dirección IP", ip_display)
        table.add_row("Máscara de Subred", str(self.subnet_mask) if self.subnet_mask else "[dim]N/A[/dim]")
        table.add_row("Router (Gateway)", str(self.router) if self.router else "[dim]N/A[/dim]")
        table.add_row("Servidor DHCP", str(self.server_ip) if self.server_ip else "[dim]N/A[/dim]")
        table.add_row("MAC Servidor DHCP", str(self.server_mac) if self.server_mac else "[dim]N/A[/dim]")
        table.add_row("---", "---")
        
        table.add_row("Estado de Concesión", lease_status)
        if self.lease_start_time > 0:
            elapsed = time.time() - self.lease_start_time
            remaining = self.lease_time - elapsed
            if remaining > 0:
                table.add_row("Tiempo Total Concesión", f"{self.lease_time}s ({self.lease_time / 3600:.1f} horas)")
                table.add_row("[bold]Tiempo Restante[/bold]", f"[bold]{int(remaining)}s[/bold]")
            else:
                 table.add_row("Estado de Concesión", "[bold red]Expirada[/bold red]")
        
        self.console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Cliente de simulación DHCP para probar el servidor didáctico.")
    parser.add_argument("--interface", required=True, help="La interfaz de red en la que escuchar (ej: eth0, enp3s0).")
    args = parser.parse_args()
    
    # Se crea una consola simple que imprime en la terminal, sin logs.
    console = Console()
    
    client = DHCPClientSimulator(interface=args.interface, console=console)
    while True:
        client.show_status()
        menu_text = Text("\nElige una acción:", justify="center")
        menu_text.append("\n  [1] Proceso Completo (DORA: Discover -> Offer -> Request -> Ack)")
        menu_text.append("\n  [2] Renovar Concesión (DHCPREQUEST Unicast)")
        menu_text.append("\n  [3] Liberar Concesión (DHCPRELEASE)")
        menu_text.append("\n  [4] Rechazar Concesión por conflicto (DHCPDECLINE)")
        menu_text.append("\n  [5] Solo Discover (Para ver la oferta del servidor)")
        menu_text.append("\n  [q] Salir")
        console.print(Panel(menu_text, title="[bold magenta]Menú de Simulación DHCP[/bold magenta]", width=70))
        choice = console.input("[bold]Opción: [/bold]")
        if choice == '1':
            if client.run_discover(): client.run_request()
        elif choice == '2': client.run_renew()
        elif choice == '3': client.run_release()
        elif choice == '4': client.run_decline()
        elif choice == '5': client.run_discover()
        elif choice.lower() == 'q':
            console.print("[bold yellow]¡Hasta luego![/bold yellow]")
            break
        else:
            console.print("[bold red]Opción no válida. Inténtalo de nuevo.[/bold red]")
        console.input("\n[dim]Presiona Enter para continuar...[/dim]")

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        sys.exit("Este script requiere Python 3.7 o superior.")
    main()
