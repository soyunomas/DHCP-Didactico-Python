# src/client_simulator.py
import argparse
import random
import sys
import time
from scapy.all import (
    BOOTP,
    DHCP,
    IP,
    UDP,
    Ether,
    conf,
    sniff,
    get_if_hwaddr
)
from scapy.arch import L2Socket

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

# Generamos una MAC ficticia localmente administrada (el primer octeto es 0x02)
# para evitar conflictos con hardware real.
FAKE_MAC = f"02:00:00:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"


class DHCPClientSimulator:
    """
    Un cliente DHCP simulado para interactuar con el servidor didáctico.
    Maneja su propio estado (IP, lease, etc.) y construye/envía paquetes.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.console = Console()
        self.mac = FAKE_MAC
        self.xid = 0  # Transaction ID
        self.reset_state()
        conf.checkIPaddr = False

    def reset_state(self):
        """Resetea el estado del cliente a sus valores iniciales."""
        self.current_ip = None
        self.server_ip = None
        self.subnet_mask = None
        self.router = None
        self.dns_servers = []
        self.domain_name = None
        self.broadcast_address = None
        self.lease_time = 0
        self.renewal_time = 0      # T1
        self.rebinding_time = 0    # T2
        self.lease_start_time = 0
        self.xid = random.randint(0, 0xFFFFFFFF)

    def _print_packet(self, title: str, packet, color: str = "cyan"):
        """Imprime un resumen del paquete de forma legible."""
        self.console.print(f"[{color} bold]TRANSMITIENDO -> {title}[/{color} bold]")
        self.console.print(packet.summary())
        if packet.haslayer(DHCP):
            self.console.print(f"  └─ DHCP Options: {packet[DHCP].options}")

    def _send_and_receive(self, packet_to_send, timeout: int = 5):
        """Envía un paquete y espera una respuesta específica."""
        try:
            iface_mac = get_if_hwaddr(self.interface)
        except Exception:
             iface_mac = self.mac # Fallback

        sock = L2Socket(iface=self.interface)
        sock.send(packet_to_send)

        filter_str = f"udp and port {CLIENT_PORT} and (ether dst {self.mac} or ether dst {iface_mac} or ether broadcast)"
        self.console.print(f"[dim]Esperando respuesta (filtro: '{filter_str}')...[/dim]")
        
        try:
            response = sniff(
                iface=self.interface,
                filter=filter_str,
                timeout=timeout,
                count=1
            )
            if response:
                return response[0]
        except Exception as e:
            self.console.print(f"[bold red]Error al escuchar respuestas: {e}[/bold red]")
        finally:
            sock.close()
        
        return None

    def run_discover(self):
        """Envía un DHCPDISCOVER y procesa el DHCPOFFER."""
        self.console.rule("[bold yellow]1. Iniciando Fase DISCOVER[/bold yellow]")
        self.reset_state() # Empezamos de cero

        # Construcción del paquete
        discover_pkt = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), flags=0x8000) / # <<< ESTA LÍNEA ES CRUCIAL
            DHCP(options=[("message-type", "discover"), ("hostname", HOSTNAME.encode()), "end"])
        )
        self.xid = discover_pkt[BOOTP].xid

        self._print_packet("DHCP DISCOVER", discover_pkt)
        offer_pkt = self._send_and_receive(discover_pkt)

        if not offer_pkt or not offer_pkt.haslayer(DHCP) or ("message-type", 2) not in offer_pkt[DHCP].options:
            self.console.print("[bold red]❌ No se recibió una oferta (DHCPOFFER) válida.[/bold red]")
            return False

        self._print_packet("DHCPOFFER Recibido", offer_pkt, "green")

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
        """Envía un DHCPREQUEST para aceptar una oferta y procesa el DHCPACK."""
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No se puede hacer un REQUEST sin una oferta previa. Ejecuta DISCOVER primero.[/bold red]")
            return False
            
        self.console.rule("[bold yellow]2. Iniciando Fase REQUEST[/bold yellow]")
        
        request_pkt = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid, flags=0x8000) / # <<< ESTA LÍNEA ES CRUCIAL
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", self.current_ip),
                ("server_id", self.server_ip),
                ("hostname", HOSTNAME.encode()),
                "end"
            ])
        )
        
        self._print_packet("DHCP REQUEST", request_pkt)
        ack_pkt = self._send_and_receive(request_pkt)
        
        if not ack_pkt or not ack_pkt.haslayer(DHCP):
            self.console.print("[bold red]❌ No se recibió respuesta al REQUEST.[/bold red]")
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
        
        return False

    def run_renew(self):
        """Envía un DHCPREQUEST (unicast) para renovar la concesión actual."""
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No hay una concesión activa para renovar.[/bold red]")
            return False

        self.console.rule("[bold yellow]Iniciando Renovación de Concesión[/bold yellow]")

        dest_mac = "ff:ff:ff:ff:ff:ff"
        
        renew_pkt = (
            Ether(src=self.mac, dst=dest_mac) /
            IP(src=self.current_ip, dst=self.server_ip) /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) /
            DHCP(options=[("message-type", "request"), "end"])
        )
        
        self._print_packet("DHCP RENEWAL REQUEST", renew_pkt)
        ack_pkt = self._send_and_receive(renew_pkt)
        
        if ack_pkt and ack_pkt.haslayer(DHCP) and ("message-type", 5) in ack_pkt[DHCP].options:
            self._print_packet("DHCPACK de Renovación Recibido", ack_pkt, "green")
            self.lease_start_time = time.time()
            self.console.print(f"[bold green]✅ Concesión para {self.current_ip} renovada con éxito.[/bold green]")
            return True
        else:
            self.console.print("[bold red]❌ Falló la renovación de la concesión.[/bold red]")
            return False

    def run_release(self):
        """Envía un DHCPRELEASE para liberar la IP actual."""
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No hay una concesión activa para liberar.[/bold red]")
            return

        self.console.rule("[bold yellow]Iniciando Liberación de Concesión[/bold yellow]")
        
        dest_mac = "ff:ff:ff:ff:ff:ff"

        release_pkt = (
            Ether(src=self.mac, dst=dest_mac) /
            IP(src=self.current_ip, dst=self.server_ip) /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(ciaddr=self.current_ip, chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) /
            DHCP(options=[("message-type", "release"), ("server_id", self.server_ip), "end"])
        )

        self._print_packet("DHCP RELEASE", release_pkt)
        sock = L2Socket(iface=self.interface)
        sock.send(release_pkt)
        sock.close()
        
        self.console.print(f"[bold green]✅ IP {self.current_ip} liberada. El estado del cliente ha sido reseteado.[/bold green]")
        self.reset_state()

    def run_decline(self):
        """Envía un DHCPDECLINE si la IP ofrecida ya está en uso."""
        if not self.current_ip or not self.server_ip:
            self.console.print("[bold red]❌ No hay una concesión que rechazar. Primero obtén una con la opción [1] o [5].[/bold red]")
            return
            
        self.console.rule("[bold red]Iniciando Rechazo de Concesión (DECLINE)[/bold red]")

        decline_pkt = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
            BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.xid) /
            DHCP(options=[
                ("message-type", "decline"),
                ("requested_addr", self.current_ip),
                ("server_id", self.server_ip),
                "end"
            ])
        )

        self._print_packet("DHCP DECLINE", decline_pkt, "magenta")
        sock = L2Socket(iface=self.interface)
        sock.send(decline_pkt)
        sock.close()

        self.console.print(f"[bold green]✅ Conflicto por la IP {self.current_ip} notificado al servidor. Estado reseteado.[/bold green]")
        self.reset_state()
        
    def show_status(self):
        """Muestra el estado actual del cliente simulado."""
        table = Table(title="[bold]Estado Actual del Cliente DHCP Simulado[/bold]")
        table.add_column("Parámetro", style="cyan")
        table.add_column("Valor")

        # --- Información de Identidad ---
        table.add_row("MAC Ficticia", self.mac)
        table.add_row("Hostname", HOSTNAME)
        table.add_row("---", "---") # Separador

        # --- Información de Red Asignada ---
        table.add_row("Dirección IP", f"[bold green]{self.current_ip}[/bold green]" if self.current_ip else "[dim]Ninguna[/dim]")
        table.add_row("Máscara de Subred", str(self.subnet_mask) if self.subnet_mask else "[dim]N/A[/dim]")
        table.add_row("Router (Gateway)", str(self.router) if self.router else "[dim]N/A[/dim]")
        table.add_row("Broadcast Address", str(self.broadcast_address) if self.broadcast_address else "[dim]N/A[/dim]")
        table.add_row("Servidores DNS", str(self.dns_servers) if self.dns_servers else "[dim]N/A[/dim]")
        table.add_row("Nombre de Dominio", str(self.domain_name) if self.domain_name else "[dim]N/A[/dim]")
        table.add_row("Servidor DHCP", str(self.server_ip) if self.server_ip else "[dim]N/A[/dim]")
        table.add_row("---", "---") # Separador

        # --- Información de la Concesión (Lease) ---
        if self.lease_start_time > 0:
            elapsed = time.time() - self.lease_start_time
            remaining = self.lease_time - elapsed
            
            if remaining > 0:
                table.add_row("Tiempo Total Concesión", f"{self.lease_time}s ({self.lease_time / 3600:.1f} horas)")
                table.add_row("[bold]Tiempo Restante[/bold]", f"[bold]{int(remaining)}s[/bold]")

                if self.renewal_time > 0:
                    t1_remaining = self.renewal_time - elapsed
                    status = f"En [bold yellow]{int(t1_remaining)}s[/bold yellow]" if t1_remaining > 0 else "[bold green]¡Ahora![/bold green]"
                    table.add_row("Renovación (T1)", f"Ocurrirá en {self.renewal_time}s. {status}")
                
                if self.rebinding_time > 0:
                    t2_remaining = self.rebinding_time - elapsed
                    status = f"En [bold yellow]{int(t2_remaining)}s[/bold yellow]" if t2_remaining > 0 else "[bold red]¡Ahora![/bold red]"
                    table.add_row("Revinculación (T2)", f"Ocurrirá en {self.rebinding_time}s. {status}")

            else:
                table.add_row("Estado de Concesión", "[bold red]Expirada[/bold red]")
        else:
             table.add_row("Estado de Concesión", "[dim]N/A[/dim]")

        self.console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Cliente de simulación DHCP para probar el servidor didáctico.")
    parser.add_argument(
        "--interface",
        required=True,
        help="La interfaz de red en la que escuchar (ej: eth0, enp3s0)."
    )
    args = parser.parse_args()

    client = DHCPClientSimulator(interface=args.interface)
    console = Console()

    while True:
        client.show_status()
        
        menu_text = Text("\nElige una acción:", justify="center")
        menu_text.append("\n  [1] Proceso Completo (DORA: Discover -> Offer -> Request -> Ack)")
        menu_text.append("\n  [2] Renovar Concesión (DHCPREQUEST Unicast)")
        menu_text.append("\n  [3] Liberar Concesión (DHCPRELEASE)")
        menu_text.append("\n  [4] Rechazar Concesión por conflicto (DHCPDECLINE)")
        menu_text.append("\n  [5] Solo Discover (Para ver la oferta del servidor)")
        menu_text.append("\n  [q] Salir")

        console.print(Panel(
            menu_text, 
            title="[bold magenta]Menú de Simulación DHCP[/bold magenta]",
            width=70
        ))
        choice = console.input("[bold]Opción: [/bold]")

        if choice == '1':
            if client.run_discover():
                client.run_request()
        elif choice == '2':
            client.run_renew()
        elif choice == '3':
            client.run_release()
        elif choice == '4':
            client.run_decline()
        elif choice == '5':
            client.run_discover()
        elif choice.lower() == 'q':
            console.print("[bold yellow]¡Hasta luego![/bold yellow]")
            break
        else:
            console.print("[bold red]Opción no válida. Inténtalo de nuevo.[/bold red]")
        
        console.input("\n[dim]Presiona Enter para continuar...[/dim]")
        console.clear()


if __name__ == "__main__":
    if sys.version_info < (3, 7):
        sys.exit("Este script requiere Python 3.7 o superior.")
    
    main()
