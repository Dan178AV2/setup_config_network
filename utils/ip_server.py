import ctypes
import nmap
import re
import os
import subprocess
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
from manuf import manuf

# Ruta donde se encuentra instalado nmap
nmap_path = "C:\\Program Files (x86)\\Nmap"

# Obtén la variable de entorno PATH actual
path = os.environ['PATH']

# Añade la ruta de nmap al final de la variable PATH
new_path = path + ";" + nmap_path

# Actualiza la variable de entorno PATH
os.environ['PATH'] = new_path

# Verifica si nmap está ahora en el PATH
print(os.environ['PATH'])
class Ip_utils(object):
    def __init__(self):
        self.interfaces = [
            'Ethernet',
            'Ethernet 2',
        ]
        self.ip_pc = self.get_ip_address()
        self.interface = self.interface_available()
        # self.ip_cameras = self.ip_Camera()
        # self.ips_pc = self.scan_ip() # Lista de direcciones IP escaneadas
        # self.ip_statics = sorted(
        #     self.scan_ip(), key=lambda ip: tuple(map(int, ip.split('.'))))

    def interface_available(self) -> str:
        """
        La función `interface_available` recupera las interfaces de red disponibles en un sistema Windows
        usando el comando `netsh` en Python.
        :return: 
            El método `interface_available` devuelve una lista de interfaces de red disponibles en un sistema
            Windows. Itera a través de cada interfaz, ejecuta un comando `netsh` para obtener la información
            de la dirección IP y extrae la dirección IP de la salida. El método devuelve la dirección IP como
            una cadena.
        """
        interfaces = []
        interface = None
        output = subprocess.check_output(
            'netsh interface show interface', shell=True).decode(errors='ignore')
        for line in output.split('\n'):
            if 'Conectado' in line:
                if len(line.split()) > 4:
                    interface = f"{line.split()[3]} {line.split()[4]}"
                else:
                    interface = f"{line.split()[3]}"
            if interface:
                interfaces.append(interface)
        return interfaces[0]

    def get_ip_address(self) -> str:
        """
        La función `get_ip_address` recupera la dirección IPv4 de las interfaces de red usando el comando
        `netsh` en Python.
        :return: 
            El método `get_ip_address` devuelve la dirección IP de las interfaces de red especificadas
            en la lista `self.interfaces`. Itera a través de cada interfaz, ejecuta un comando `netsh` para
            obtener la información de la dirección IP y extrae la dirección IP de la salida. El método devuelve
            la dirección IP como una cadena.
        """
        ip_addresses = ''
        for interface in self.interfaces:
            try:
                output = subprocess.check_output(
                    f'netsh interface ipv4 show address name="{interface}"', shell=True).decode(errors='ignore')
                for line in output.split('\n'):
                    if 'Direccin IP' in line:
                        ip_address = re.search(
                            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                        if ip_address:
                            ip_addresses = ip_address.group()
                            break
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar el comando para la interfaz {interface}: {e}")
        return ip_addresses

    def scan_ip(self) -> list[str]:
        """
        Esta función de Python escanea un rango de IP específico usando nmap y devuelve una lista de
        direcciones IP descubiertas excluyendo una específica.
        :return: 
            La función `scan_ip` devuelve una lista de direcciones IP que se escanean dentro del rango
            de IP especificado '190.168.0.1/24', excluyendo la dirección IP '190.168.0.2'.
        """

        ip_result: list[str] = []
        ip_range = '190.168.0.1/24'

        nm = nmap.PortScanner()

        nm.scan(hosts=ip_range, arguments='-sP')

        host_list = nm.all_hosts()
        for host in host_list:
            if host != '190.168.0.2' and host not in self.ip_cameras and host != self.ip_pc:
                ip_result.append(f"{host}")
        return ip_result

    def is_admin(self) -> bool:
        """
        La función `is_admin()` comprueba si el usuario actual tiene privilegios administrativos en un
        sistema Windows.
        :return: 
            La función `is_admin()` devuelve un valor booleano. Intenta verificar si el usuario actual
            tiene privilegios administrativos en un sistema Windows
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def run(self, command: str):
        """
        La función `ejecutar` ejecuta un comando con derechos de administrador en Python.

        :param `command` str: 
            Este comando se ejecutará usando la función `subprocess.run` si el usuario
            es administrador. Si el usuario no es administrador, el programa intentará volver a ejecutarse con
            admin.

        """
        if self.is_admin():
            print('Ejecutando el comando: ', command)
            subprocess.run(command, shell=True)
        else:
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)

    def dhcp(self):
        """
        La función `dhcp` verifica si DHCP está habilitado ejecutando un comando específico en Python.
        """
        print('Ver si el DHCP está habilitado: ')
        dhcp_command = ('netsh interface ipv4 show interface')
        self.run(command=dhcp_command)

    def read_ip(self):
        """
        La función `read_ip` lee la configuración de una interfaz de red usando el comando `netsh` en
        Python.
        """
        print('la Configuracion  de la nic es:')
        ip = f'netsh interface ipv4 show address name="{self.interface}"'
        subprocess.run(ip, shell=True)

    def ip_static_server(self):
        """
        La función `ip_static_server` establece una dirección IP estática, una máscara de subred y una
        puerta de enlace para una interfaz de red específica en Windows usando el comando `netsh`.


        """
        print(f'Configurando IP static a la nic {self.interface}')
        s = f'netsh interface ipv4 set address name="{self.interface}" source=static address=190.168.0.1 mask=255.255.255.0 gateway=190.168.0.30'
        self.run(command=s)

    def ip_static_client(self):
        """
        La función establece una dirección IP estática, una máscara de subred y una puerta de enlace para
        una interfaz de red específica en Windows mediante el comando `netsh`.

        :param `interface` str: 
            Se utiliza para especificar la interfaz de red en 
            la que se aplicará la configuración de IP estática.

        """
        print(f'Configurando IP static a la nic {self.interface}')
        s = f'netsh interface ipv4 set address name="{self.interface}" source=static address=190.168.0.3 mask=255.255.255.0 gateway=190.168.0.254'
        self.run(command=s)

    def dhcp_enabled(self):
        """
        La función `dhcp_enabled` configura DHCP en una interfaz de red específica en Python.

        :param `interface` str: 
            El nombre de la interfaz de red para la cual se está configurando DHCP 
            (Protocolo de configuración dinámica de host)

        """
        print(f"Configurando DHCP a la Nic {self.interface}")
        command_dhcp = f'netsh interface ipv4 set address name="{self.interface}" source=dhcp'
        self.run(command=command_dhcp)

    def has_dhcp_enabled(self):
        """
        La función `has_dhcp_enabled` verifica si DHCP está habilitado en una interfaz de red específica en Windows.

        :param `interface` str: 
            El nombre de la interfaz de red para la cual se está verificando si DHCP está habilitado.

        """

        for interface in self.interfaces:
            try:
                output = subprocess.check_output(
                    f'netsh interface ipv4 show address name="{interface}"', shell=True).decode(errors='ignore')
                # Busca la línea que contiene la dirección IP
                for line in output.split('\n'):
                    if 'DHCP habilitado' in line:
                        if line.split()[-1] == 'No':
                            print(f"DHCP NO habilitado en la interfaz {interface}")
                        else:
                            print(f"DHCP habilitado en la interfaz {interface}")
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar el comando para la interfaz {interface}: {e}")

    def get_mac_and_vendor(self, ip_address: str) -> tuple[str, str]:
        # Enviar una solicitud ARP a la dirección IP para obtener la dirección MAC
        arp_request = ARP(pdst=ip_address)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        if not answered_list:  # Comprobar si la lista está vacía
            return "This device", "This device"

        mac_address = answered_list[0][1].hwsrc

        # Usar la biblioteca manuf para obtener el fabricante del dispositivo
        p = manuf.MacParser()
        vendor = p.get_manuf(mac_address)

        return mac_address, vendor
    
    def ip_Camera(self):
        """
        La función `ip_Camera` recupera la dirección IP de la cámara conectada a la red.
        """
        # Rango de direcciones IP a probar
        start_ip = "190.168.0.100"
        end_ip = "190.168.0.254"

        # Función para convertir una dirección IP en formato decimal a formato de cadena
        def ip_to_str(ip):
            return ".".join(map(str, ip))

        # Función para convertir una dirección IP en formato de cadena a formato decimal
        def str_to_ip(ip_str):
            return tuple(map(int, ip_str.split(".")))

        # Función para probar la conexión a una dirección IP específica
        def test_ip(ip):
            try:
                # Intenta establecer una conexión al puerto 80
                socket.create_connection((ip, 80), 2)
                print(f"La dirección IP {ip} está respondiendo.")
                return ip
            except socket.error:
                print(f"No se pudo establecer una conexión a la dirección IP {ip}.")
                return None

        # Convierte las direcciones IP de inicio y fin a formato decimal
        start_ip_dec = str_to_ip(start_ip)
        end_ip_dec = str_to_ip(end_ip)

        # Crea una lista de direcciones IP para probar
        ip_list = [ip_to_str(start_ip_dec[:-1] + (ip,)) for ip in range(start_ip_dec[3], end_ip_dec[3] + 1)]

        # Usa ThreadPoolExecutor para ejecutar test_ip en paralelo para cada dirección IP
        ip_available = []
        with ThreadPoolExecutor() as executor:
            for ip in ip_list:
                result = executor.submit(test_ip, ip)
                if result.result() is not None:
                    ip_available.append(result.result())
                if len(ip_available) == 2:
                    break

        print("Direcciones IP disponibles:", ip_available)
        return ip_available

    
# if __name__ == '__main__':
#     ip = Ip_utils()
#     print(ip.get_ip_address())