# src/database.py
import sqlite3
import time
from ipaddress import IPv4Address
import os

class LeaseDatabase:
    def __init__(self, db_path='data/dhcp_leases.db', lock=None):
        if not lock:
            raise ValueError("Se requiere un objeto Lock para la base de datos.")
        
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.lock = lock
        self._create_table()
        self._create_history_table() # <<< MEJORA: Llamamos a la creación de la nueva tabla

    def _create_table(self):
        with self.lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS leases (
                    mac TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                )
            ''')
            self.conn.commit()

    # <<< MEJORA: Nuevo método para crear la tabla de histórico >>>
    def _create_history_table(self):
        with self.lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS leases_history (
                    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_timestamp INTEGER NOT NULL
                )
            ''')
            self.conn.commit()
    # --- Fin de la mejora ---

    # <<< MEJORA: Nuevo método para añadir un registro al histórico >>>
    def add_history_log(self, mac, ip, event_type):
        event_timestamp = int(time.time())
        with self.lock:
            self.cursor.execute(
                "INSERT INTO leases_history (mac, ip_address, event_type, event_timestamp) VALUES (?, ?, ?, ?)",
                (mac, ip, event_type, event_timestamp)
            )
            self.conn.commit()
    # --- Fin de la mejora ---

    def add_lease(self, mac, ip, lease_time):
        expires_at = int(time.time()) + lease_time
        with self.lock:
            self.cursor.execute(
                "REPLACE INTO leases (mac, ip_address, expires_at) VALUES (?, ?, ?)",
                (mac, ip, expires_at)
            )
            self.conn.commit()

    def get_lease(self, mac):
        with self.lock:
            self.cursor.execute("SELECT ip_address, expires_at FROM leases WHERE mac = ?", (mac,))
            result = self.cursor.fetchone()
        if result and result[1] > time.time():
            return {'ip': result[0], 'expires_at': result[1]}
        return None

    def release_lease(self, mac):
        with self.lock:
            self.cursor.execute("DELETE FROM leases WHERE mac = ?", (mac,))
            self.conn.commit()

    def get_active_leases(self):
        with self.lock:
            self.cursor.execute("SELECT mac, ip_address FROM leases WHERE expires_at > ?", (int(time.time()),))
            return {row[1]: row[0] for row in self.cursor.fetchall()}

    def find_available_ip(self, pool_start, pool_end, reservations):
        start = int(IPv4Address(pool_start))
        end = int(IPv4Address(pool_end))
        
        active_ips = set(self.get_active_leases().keys())
        reserved_ips = set(reservations.values())
        
        for ip_int in range(start, end + 1):
            ip_str = str(IPv4Address(ip_int))
            if ip_str not in active_ips and ip_str not in reserved_ips:
                return ip_str
        return None
