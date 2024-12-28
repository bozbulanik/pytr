"""
TO-DO:
 CPU CORES
"""

import os
import subprocess
import platform
import psutil
from datetime import datetime
import socket
import re
import pathlib

class SystemData:
    def __init__(self, report_title):
        self.report_title = report_title
        self.title = "TR-100 MACHINE REPORT"
        self.collect_data()
        
    def run_command(self, command, windows_command=None):
        if platform.system() == "Windows" and windows_command:
            command = windows_command

        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()


    def get_os_info(self):
        os_name = platform.system()
        if os_name == "Linux":
            os_name = ""
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith(('ID=', 'VERSION=', 'VERSION_CODENAME=')):
                            os_name += line.split('=')[1].strip().strip('"').capitalize()
            except Exception:
                os_name = "Linux"
        
        os_kernel = f"{platform.system()} {platform.release()}"

        self.os_info = {
            'name': os_name or "NA",
            'kernel': os_kernel or "NA"
        }

    def get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP 

    def get_dns_servers(self):
        dns_servers = []
        if platform.system() == "Windows":
            output = self.run_command('ipconfig /all')
            for line in output.split('\n'):
                if 'DNS Servers' in line:
                    servers = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', line)
                    dns_servers.extend(servers)
        else:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            except Exception:
                pass
        return dns_servers

    def get_current_user(self):
        try:
            return os.getlogin()
        except Exception:
            return os.environ.get('USERNAME') or os.environ.get('USER')

    def get_net_info(self):
        hostname = platform.node()
        machine_ip = self.get_ip()
        client_ip = ""
        dns_servers = self.get_dns_servers()
        current_user = self.get_current_user()

        self.network_info = {
            'hostname': hostname or "NA",
            'machine_ip': machine_ip or "NA",
            'client_ip': client_ip or "Not connected",
            'dns_ip': dns_servers[0] if dns_servers else "NA",
            'current_user': current_user or "NA"
        }



    def get_cpu_info(self):
        if platform.system() == "Linux" or platform.processor() == "":
            cpu_model = self.run_command("lscpu | grep 'Model name:' | cut -d ':' -f 2 | sed 's/^ *//' | awk '{print $1, $2, $3, $4}'")
        else:
            cpu_model = platform.processor()
        
        # Get CPU cores information
        cpu_cores_per_socket = self.run_command("lscpu | grep 'Core(s) per socket' | cut -f 2 -d ':' | awk '{$1=$1}1' ")
        cpu_sockets = self.run_command("lscpu | grep 'Socket(s)' | cut -f 2 -d ':' | awk '{$1=$1}1'")
        cpu_cores_str = cpu_cores_per_socket + " vCPU(s) / " + cpu_sockets + " Socket(s)"
        
        # Detect virtualization
        cpu_hypervisor = ""
        if platform.system() == "Linux":
            result = self.run_command("systemd-detect-virt")
            cpu_hypervisor = result if result != "none" else "Bare Metal"
        elif platform.system() == "Windows":
            result = self.run_command('systeminfo | findstr /i "Hyper-V"')
            cpu_hypervisor = result if result != "none" else "Bare Metal"
        
        # Get CPU frequency
        cpu_freq = psutil.cpu_freq()
        cpu_freq_str = f"{cpu_freq.current / 1000:.2f}GHz" if cpu_freq else "NA"
        
        self.cpu_info = {
            'model': cpu_model or "NA",
            'cores': cpu_cores_str or "NA",
            'hypervisor': cpu_hypervisor or "NA",
            'freq': cpu_freq_str or "NA",
            'load_1m': "NA",
            'load_5m': "NA",
            'load_15m': "NA",
        }

    def get_storage_info(self):
        disk = psutil.disk_usage('/')
        total_disk = disk.total / (2**30)
        used_disk = disk.used / (2**30)
        disk_usage = (used_disk / total_disk) * 100
        if(platform.system() == "Windows"):
            drive = pathlib.Path.home().drive
            volume = f"{drive} {used_disk:.2f}/{total_disk:.2f} GB [{disk_usage:.2f}%]"
        else:
            volume = f"{used_disk:.2f}/{total_disk:.2f} GB [{disk_usage:.2f}%]"


        self.storage_info = {
            'volume': volume,
            'disk_usage': "NA",
        }

    def get_memory_info(self):
        mem = psutil.virtual_memory()
        total_mem = mem.total / (2**30)
        used_mem = mem.used / (2**30)
        mem_usage = mem.percent
        mem_info = f"{used_mem:.2f}/{total_mem:.2f} GiB [{mem_usage:.2f}%]"

        self.memory_info = {
            'mem_info': mem_info or "NA",
            'mem_usage': "NA"
        }

    def is_valid_ip(self, ip):
        pattern = r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        if re.match(pattern, str(ip)) and ip != '0.0.0.0':
            return True
        return False

    def get_last_login_ip_for_windows():
        try:
            command = [
                "powershell",
                "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1 | "
                "ForEach-Object {($_ | Select-String -Pattern 'Source Network Address').Line}"
            ]
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                raise RuntimeError(f"Error executing command: {result.stderr.strip()}")

            output = result.stdout.strip()
            match = re.search(r"Source Network Address:\s+([\d.]+)", output)
            if match:
                return match.group(1)
            else:
                return "NA"

        except Exception:
            return "NA"

    def get_session_info(self):
        if platform.system() == "Windows":
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            days = uptime.days
            hours = uptime.seconds // 3600
            minutes = (uptime.seconds % 3600) // 60
            uptime = f"{days}d {hours}h {minutes}m"

            last_login_ip = self.get_last_login_ip_for_windows()
            if(self.is_valid_ip(last_login_ip)):
                last_login = self.run_command('net user %username% | findstr /B /C:"Last logon"')
                last_login_time = last_login.replace("Last logon", "").strip() if last_login != "NA" else "NA"
        else:
            last_login_ip = self.run_command("last -1 -i $USER | head -1 | awk '{print $3}'")
            if(self.is_valid_ip(last_login_ip)):
                last_login_time = self.run_command("lastlog -u $USER | awk 'NR==2 {print $6, $7, $10, $8}'")
            else:
                last_login_time = self.run_command("lastlog -u $USER | awk 'NR==2 {print $4, $5, $8, $6}'")

            uptime = self.run_command("uptime -p | sed 's/up\\s*//; s/\\s*day(s*)/d/; s/\\s*hour(s*)/h/; s/\\s*minute(s*)/m/'")


        self.session_info = {
            'last_login_time': last_login_time or "Never logged in",
            'last_login_ip': last_login_ip if self.is_valid_ip(last_login_ip) else "NA",
            'uptime': uptime or "NA"
        }


    def collect_data(self):
        self.get_os_info()
        self.get_net_info()
        self.get_cpu_info()
        self.get_storage_info()
        self.get_memory_info()
        self.get_session_info()

    def get_bar_graph(self, used, total, length):
        try:
            percent = (used / total * 100) if total > 0 else 0
            num_blocks = int((percent / 100) * length)
            return "█" * num_blocks + "░" * (length - num_blocks)
        except Exception:
            return "░" * length

    def calculate_bar_garphs(self, length):
        # Storage usage
        disk = psutil.disk_usage('/')
        self.storage_info['disk_usage'] = self.get_bar_graph(disk.used, disk.total, length)


        # CPU load
        if hasattr(psutil, 'getloadavg'):
            load_avg = psutil.getloadavg()
        else:
            # Windows alternative
            load_avg = (psutil.cpu_percent() / 100.0,) * 3
        cpu_cores = psutil.cpu_count(logical=True)
        
        self.cpu_info['load_1m'] = self.get_bar_graph(load_avg[0], cpu_cores, length)
        self.cpu_info['load_5m'] = self.get_bar_graph(load_avg[1], cpu_cores, length)
        self.cpu_info['load_15m'] = self.get_bar_graph(load_avg[2], cpu_cores, length)

        # Memory usage
        mem = psutil.virtual_memory()
        self.memory_info['mem_usage'] = self.get_bar_graph(mem.used, mem.total, length)
        
class TableFormatter:
    def __init__(self, min_name_len=5, max_name_len=13, min_data_len=20, max_data_len=32, borders_padding=7):
        self.MIN_NAME_LEN = min_name_len
        self.MAX_NAME_LEN = max_name_len
        self.MIN_DATA_LEN = min_data_len
        self.MAX_DATA_LEN = max_data_len
        self.BORDERS_AND_PADDING = borders_padding
        self.CURRENT_LEN = 0

    def calculate_max_length(self, *args):
        max_len = 0
        for string in args:
            length = len(str(string))
            if length > max_len:
                max_len = length
        return min(max_len, self.MAX_DATA_LEN)

    def format_header(self):
        length = self.get_length()
        top = "┌" + "┬" * (length - 2) + "┐"
        bottom = "├" + "┴" * (length - 2) + "┤"
        return f"{top}\n{bottom}"

    def format_footer(self, length):
        footer = "└" + "─" * (length - 3)
        footer += "┴" if length > 15 else ""
        footer += "┘"
        return footer + "\n"

    def format_divider(self, side="middle"):
        length = self.CURRENT_LEN + self.MAX_NAME_LEN + self.BORDERS_AND_PADDING
        symbols = {
            "top": ("├", "┬", "┤"),
            "bottom": ("└", "┴", "┘"),
            "middle": ("├", "┼", "┤")
        }
        left, middle, right = symbols.get(side, symbols["middle"])
        
        divider = left + "─" * (length - 3)
        divider = divider[:16] + middle + divider[16:]
        return divider + right

    def format_centered_data(self, text):
        max_len = self.CURRENT_LEN + self.MAX_NAME_LEN - self.BORDERS_AND_PADDING
        total_width = max_len + 12
        return f"│{text.center(total_width)}│"

    def format_data_row(self, name, data):
        max_data_len = self.CURRENT_LEN
        name_len = len(name)        
        if name_len < self.MIN_NAME_LEN:
            name = name.ljust(self.MIN_NAME_LEN)
        elif name_len > self.MAX_NAME_LEN:
            name = name[:self.MAX_NAME_LEN - 3] + "..."
        else:
            name = name.ljust(self.MAX_NAME_LEN)

        data_len = len(data)
        if data_len >= self.MAX_DATA_LEN or data_len == self.MAX_DATA_LEN - 1:
            data = data[:self.MAX_DATA_LEN - 3] + "..."
        else:
            data = data.ljust(max_data_len)

        return f"│ {name:<{self.MAX_NAME_LEN}} │ {data} │"

    def get_length(self):
        return self.CURRENT_LEN + self.MAX_NAME_LEN + self.BORDERS_AND_PADDING
    

class SystemReport:
    def __init__(self, system_data = None, formatter = None, report_title = "BOZBULANIK PRESENTS"):
        self.data = system_data or SystemData(report_title)
        self.formatter = formatter or TableFormatter()
        
    def calculate_content_length(self):
        all_values = [
            self.data.report_title,
            self.data.title,
            *self.data.os_info.values(),
            *self.data.network_info.values(),
            *self.data.cpu_info.values(),
            *self.data.storage_info.values(),
            *self.data.memory_info.values(),
            *self.data.session_info.values()
        ]
        self.formatter.CURRENT_LEN = self.formatter.calculate_max_length(*all_values)
        self.data.calculate_bar_garphs(self.formatter.CURRENT_LEN)

    def generate_report(self):
        self.calculate_content_length()
        
        report = []
        report.append(self.formatter.format_header())
        report.append(self.formatter.format_centered_data(self.data.report_title))
        report.append(self.formatter.format_centered_data(self.data.title))
        
        # OS Section
        report.append(self.formatter.format_divider("top"))
        report.append(self.formatter.format_data_row("OS", self.data.os_info['name']))
        report.append(self.formatter.format_data_row("KERNEL", self.data.os_info['kernel']))
        
        # Network Section
        report.append(self.formatter.format_divider())
        report.append(self.formatter.format_data_row("HOSTNAME", self.data.network_info['hostname']))
        report.append(self.formatter.format_data_row("MACHINE IP", self.data.network_info['machine_ip']))
        report.append(self.formatter.format_data_row("CLIENT  IP", self.data.network_info['client_ip']))
        report.append(self.formatter.format_data_row("USER", self.data.network_info['current_user']))
        
        # CPU Section
        report.append(self.formatter.format_divider())
        report.append(self.formatter.format_data_row("PROCESSOR", self.data.cpu_info['model']))
        report.append(self.formatter.format_data_row("CORES", self.data.cpu_info['cores']))
        report.append(self.formatter.format_data_row("HYPERVISOR", self.data.cpu_info['hypervisor']))
        report.append(self.formatter.format_data_row("CPU FREQ", self.data.cpu_info['freq']))
        report.append(self.formatter.format_data_row("LOAD  1m", self.data.cpu_info['load_1m']))
        report.append(self.formatter.format_data_row("LOAD  5m", self.data.cpu_info['load_5m']))
        report.append(self.formatter.format_data_row("LOAD 15m", self.data.cpu_info['load_15m']))
        
        # Storage Section
        report.append(self.formatter.format_divider())
        report.append(self.formatter.format_data_row("VOLUME", self.data.storage_info['volume']))
        report.append(self.formatter.format_data_row("DISK USAGE", self.data.storage_info['disk_usage']))
        
        # Memory Section
        report.append(self.formatter.format_divider())
        report.append(self.formatter.format_data_row("MEMORY", self.data.memory_info['mem_info']))
        report.append(self.formatter.format_data_row("USAGE", self.data.memory_info['mem_usage']))
        
        # Session Section
        report.append(self.formatter.format_divider())
        report.append(self.formatter.format_data_row("LAST LOGIN", self.data.session_info['last_login_time']))
        report.append(self.formatter.format_data_row("LAST LOGIN IP", self.data.session_info['last_login_ip']))

        report.append(self.formatter.format_data_row("UPTIME", self.data.session_info['uptime']))
        
        report.append(self.formatter.format_divider("bottom"))
        
        return "\n".join(report)


def main():
    system = SystemReport(report_title="BOZBULANIK PERSONAL LAPTOP")
    print(system.generate_report())

if __name__ == "__main__":
    main()
