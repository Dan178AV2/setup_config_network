import ctypes
import nmap
import re
import subprocess
import sys
from scapy.all import ARP, Ether, srp
from manuf import manuf


class Ip_utils(object):
    def __init__(self):
        self.interfaces = [
            'Ethernet',
            'Ethernet 2',
        ]
        self.ip_pc = self.get_ip_address()
        self.interface = self.interface_available()
        print(f"self.interface: {self.interface}")
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
            # Ejecuta el comando netsh
            output = subprocess.check_output(
                f'netsh interface ipv4 show address name="{interface}"', shell=True).decode(errors='ignore')
            # Busca la línea que contiene la dirección IP
            for line in output.split('\n'):
                if 'Dirección IP' in line:
                    ip_address = re.search(
                        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                    if ip_address:
                        ip_addresses = ip_address.group()
                        break
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
            if host != '190.168.0.2':
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
        s = f'netsh interface ipv4 set address name="{self.interface}" source=static address=190.168.0.1 mask=255.255.255.0 gateway=190.168.0.1'
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
            output = subprocess.check_output(
                f'netsh interface ipv4 show address name="{interface}"', shell=True).decode(errors='ignore')
            # Busca la línea que contiene la dirección IP
            for line in output.split('\n'):
                if 'DHCP habilitado' in line:
                    if line.split()[-1] == 'No':
                        print(f"DHCP NO habilitado en la interfaz {interface}")
                    else:
                        print(f"DHCP habilitado en la interfaz {interface}")

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


# if __name__ == '__main__':
#     ip_utils = Ip_utils()
    # print(ip_utils.interface)
    # ip_result = ip_utils.ip_statics
    # ip_utils.has_dhcp_enabled()
    # print(ip_result)
    # for ip in ip_result:
    #     mac, vendor = ip_utils.get_mac_and_vendor(ip)
    #     print(f"IP: {ip} MAC: {mac} Vendor: {vendor}")
