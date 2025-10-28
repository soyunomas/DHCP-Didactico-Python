# manager.py
import argparse
import json
import sqlite3
import sys
from datetime import datetime
from ipaddress import IPv4Address

# Intentamos importar 'rich', si no está, damos instrucciones claras.
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Error: La librería 'rich' no está instalada.")
    print("Por favor, instálala para usar este gestor: pip install rich")
    sys.exit(1)

# --- Constantes ---
DB_PATH = 'data/dhcp_leases.db'
CONFIG_PATH = 'config/config.json'

class DHCPManager:
    """
    Clase que encapsula la lógica para interactuar con la base de datos
    y la configuración del servidor DHCP.
    """
    def __init__(self, db_path, config_path):
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"Error: No se encontró el archivo de configuración en '{config_path}'.")
        except json.JSONDecodeError:
            raise RuntimeError(f"Error: El archivo de configuración '{config_path}' no es un JSON válido.")

        try:
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
        except sqlite3.OperationalError as e:
            raise RuntimeError(f"Error al conectar con la base de datos en '{db_path}': {e}")

    def get_pool_stats(self):
        """Calcula las estadísticas de uso del pool de IPs."""
        try:
            pool_start = int(IPv4Address(self.config['subnet']['pool_start']))
            pool_end = int(IPv4Address(self.config['subnet']['pool_end']))
            total_ips = pool_end - pool_start + 1
        except KeyError:
            return {'total': 0, 'used': 0, 'percentage': 0}

        self.cursor.execute("SELECT COUNT(*) FROM leases")
        used_ips = self.cursor.fetchone()[0]
        
        percentage = (used_ips / total_ips) * 100 if total_ips > 0 else 0
        return {'total': total_ips, 'used': used_ips, 'percentage': percentage}

    def get_active_leases(self, search_term=None):
        """Obtiene una lista de todas las concesiones activas, con opción de búsqueda."""
        query = "SELECT mac, ip_address, expires_at FROM leases"
        params = []
        if search_term:
            query += " WHERE mac LIKE ? OR ip_address LIKE ?"
            params.extend([f'%{search_term}%', f'%{search_term}%'])
        
        query += " ORDER BY ip_address"
        self.cursor.execute(query, params)
        leases = self.cursor.fetchall()
        
        return [
            {
                'mac': row[0],
                'ip': row[1],
                'expires': datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M:%S')
            } for row in leases
        ]

    def get_recent_history(self, limit=5):
        """Obtiene los eventos más recientes del histórico."""
        try:
            self.cursor.execute(
                "SELECT event_timestamp, event_type, mac, ip_address FROM leases_history ORDER BY event_timestamp DESC LIMIT ?",
                (limit,)
            )
            history = self.cursor.fetchall()
            return [
                {
                    'time': datetime.fromtimestamp(row[0]).strftime('%H:%M:%S'),
                    'type': row[1],
                    'mac': row[2],
                    'ip': row[3]
                } for row in history
            ]
        except sqlite3.OperationalError:
             # La tabla de histórico podría no existir en bases de datos antiguas
            return []


    def free_lease(self, identifier):
        """Libera una concesión por su IP o MAC."""
        query = "DELETE FROM leases WHERE ip_address = ? OR mac = ?"
        self.cursor.execute(query, (identifier, identifier))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def close(self):
        """Cierra la conexión a la base de datos."""
        self.conn.close()


def display_dashboard(manager, console):
    """Muestra el panel de control principal."""
    stats = manager.get_pool_stats()
    recent_history = manager.get_recent_history()

    # Panel de estadísticas
    used_color = "green"
    if stats['percentage'] > 50: used_color = "yellow"
    if stats['percentage'] > 80: used_color = "red"
    
    stats_text = Text(justify="center")
    stats_text.append(f"{stats['used']} / {stats['total']} IPs asignadas\n", style="bold")
    stats_text.append(f"({stats['percentage']:.2f}%)", style=used_color)

    panel_stats = Panel(stats_text, title="[bold cyan]Uso del Pool[/bold cyan]", border_style="cyan")

    # Tabla de histórico reciente
    history_table = Table(title="[bold magenta]Últimos Eventos[/bold magenta]", border_style="magenta")
    history_table.add_column("Hora", style="dim")
    history_table.add_column("Evento", style="yellow")
    history_table.add_column("MAC Address")
    history_table.add_column("IP Address")

    for item in recent_history:
        history_table.add_row(item['time'], item['type'], item['mac'], item['ip'])
    
    console.print(panel_stats)
    if recent_history:
        console.print(history_table)
    else:
        console.print("[yellow]No hay eventos en el histórico todavía.[/yellow]")


def display_leases(manager, console, search_term=None):
    """Muestra la tabla de concesiones activas."""
    leases = manager.get_active_leases(search_term)
    
    table = Table(title="[bold green]Concesiones Activas[/bold green]", show_header=True, header_style="bold green")
    table.add_column("MAC Address", style="cyan", no_wrap=True)
    table.add_column("IP Address", style="magenta")
    table.add_column("Expira en", style="yellow")

    if not leases:
        console.print("[yellow]No se encontraron concesiones activas.[/yellow]")
        return
        
    for lease in leases:
        table.add_row(lease['mac'], lease['ip'], lease['expires'])
    
    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Herramienta de gestión para el servidor DHCP Didáctico.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--leases',
        action='store_true',
        help='Muestra todas las concesiones de IP activas.'
    )
    parser.add_argument(
        '--search',
        type=str,
        help='Filtra la lista de concesiones por IP o MAC.'
    )
    parser.add_argument(
        '--free-lease',
        metavar='IP_o_MAC',
        type=str,
        help='Libera una concesión activa especificando su IP o MAC.'
    )

    # Si no se dan argumentos, mostramos la ayuda. sys.argv tiene el nombre del script en [0].
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        # Mostramos el dashboard como comportamiento por defecto
        print("\n--- Ejecutando Dashboard por defecto ---")
        # sys.argv.append('--dashboard') # Truco para que ejecute el dashboard
    
    args = parser.parse_args()
    console = Console()

    try:
        manager = DHCPManager(DB_PATH, CONFIG_PATH)
    except RuntimeError as e:
        console.print(f"[bold red]Error de inicialización:[/bold red] {e}")
        sys.exit(1)

    try:
        if args.leases or args.search:
            display_leases(manager, console, args.search)
        elif args.free_lease:
            console.print(f"¿Está seguro que desea liberar la concesión para '[bold yellow]{args.free_lease}[/bold yellow]'? [y/N]: ", end="")
            if input().lower() == 'y':
                if manager.free_lease(args.free_lease):
                    console.print(f"[green]✅ Concesión para '{args.free_lease}' liberada con éxito.[/green]")
                else:
                    console.print(f"[red]❌ No se encontró una concesión activa para '{args.free_lease}'.[/red]")
            else:
                console.print("[yellow]Operación cancelada.[/yellow]")
        else:
            # Comportamiento por defecto: mostrar el dashboard
            display_dashboard(manager, console)
    finally:
        manager.close()

if __name__ == "__main__":
    main()
