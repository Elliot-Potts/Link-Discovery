import psutil
from utils.logger import logger


def get_windows_interfaces():
    interfaces = psutil.net_if_addrs()
    return [iface for iface in interfaces.keys() if not iface.startswith(('lo', 'vir', 'vmnet'))]


def get_active_interface():
    stats = psutil.net_io_counters(pernic=True)
    active_interface = max(stats, key=lambda x: stats[x].bytes_sent + stats[x].bytes_recv)
    logger.debug(f"Active Interface: {active_interface}")
    return active_interface
