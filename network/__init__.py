from .interface import get_windows_interfaces, get_active_interface
from .cdp_capture import capture_and_parse_cdp

__all__ = ['get_windows_interfaces', 'get_active_interface', 'capture_and_parse_cdp']