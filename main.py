# CDP Discovery Tool using Scapy for packet capture, Flet for UI, and psutil for network interface discovery
# Author: Elliot Potts (https://github.com/Elliot-Potts)

import flet as ft
import scapy.all as scapy
from scapy.layers.l2 import Dot3, LLC, SNAP
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, CDPMsgCapabilities, CDPMsgNativeVLAN, CDPMsgDuplex, CDPMsgMgmtAddr
import psutil
import asyncio
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Suppress Flet's debug messages (UI updates too verbose)
logging.getLogger("flet_core").setLevel(logging.WARNING)
logging.getLogger("flet_runtime").setLevel(logging.WARNING)

# Get a list of network interfaces on Windows
def get_windows_interfaces():
    interfaces = psutil.net_if_addrs()
    return [iface for iface in interfaces.keys() if not iface.startswith(('lo', 'vir', 'vmnet'))]

# Capture and return CDP packet on the specified interface
async def capture_cdp_packet(interface, timeout=60):
    def stop_filter(pkt):
        return CDPv2_HDR in pkt

    packet = await asyncio.get_event_loop().run_in_executor(
        None, 
        lambda: scapy.sniff(iface=interface, filter="ether dst 01:00:0c:cc:cc:cc", stop_filter=stop_filter, timeout=timeout, count=1)
    )
    return packet[0] if packet else None

# Parse CDP packet and return relevant information
def parse_cdp_packet(packet):
    cdp_info = {}
    if CDPv2_HDR in packet:
        cdp_layer = packet[CDPv2_HDR]
        logger.debug(f"CDP Layer: {cdp_layer.summary()}")
        cdp_info['Version'] = cdp_layer.vers
        cdp_info['TTL'] = cdp_layer.ttl

        for tlv in cdp_layer.msg:
            logger.debug(f"Processing TLV: {type(tlv).__name__}")
            if isinstance(tlv, CDPMsgDeviceID):
                cdp_info['Device ID'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgSoftwareVersion):
                cdp_info['Software Version'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgPlatform):
                cdp_info['Platform'] = tlv.val.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgPortID):
                cdp_info['Port ID'] = tlv.iface.decode('utf-8', errors='ignore')
            elif isinstance(tlv, CDPMsgCapabilities):
                cdp_info['Capabilities'] = str(tlv.cap)
            elif isinstance(tlv, CDPMsgNativeVLAN):
                cdp_info['Native VLAN'] = tlv.vlan
            elif isinstance(tlv, CDPMsgDuplex):
                cdp_info['Duplex'] = 'Full' if tlv.duplex == 1 else 'Half'
            elif isinstance(tlv, CDPMsgMgmtAddr):
                mgmt_addrs = []
                for addr in tlv.addr:
                    if hasattr(addr, 'addr'):
                        mgmt_addrs.append(str(addr.addr))
                cdp_info['Management Addresses'] = ', '.join(mgmt_addrs)

    logger.debug(f"Parsed CDP Info: {cdp_info}")
    return cdp_info

# Main function to init Flet app and create UI, capture CDP packet, and display results
def main(page: ft.Page):
    page.title = "CDP Discovery Tool"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 0
    page.spacing = 0
    page.vertical_alignment = ft.MainAxisAlignment.START
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    # Header component
    header = ft.Container(
        content=ft.Text("CDP Discovery Tool", color=ft.colors.WHITE, size=20, weight=ft.FontWeight.BOLD),
        padding=10,
        bgcolor=ft.colors.BLACK,
        width=page.width
    )

    # CDP results area
    results_area = ft.Container(
        content=ft.Column(spacing=10),
        visible=False
    )

    # Progress indicator and countdown
    progress_ring = ft.ProgressRing(visible=False)
    countdown_text = ft.Text("Waiting for CDP packet... (max 60 seconds)", visible=False)
    progress_column = ft.Column([
        progress_ring,
        countdown_text
    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER)

    # For 60 seconds, keep capturing CDP until all relevant information is found
    async def capture_and_parse(interface):
        for i in range(60):
            cdp_packet = await capture_cdp_packet(interface, timeout=1)
            if cdp_packet:
                cdp_info = parse_cdp_packet(cdp_packet)
                if cdp_info and len(cdp_info) > 2:  # We have more than just Version and TTL
                    return cdp_info
            countdown_text.value = f"Waiting for CDP packet... ({60 - i} seconds remaining)"
            page.update()
        return None

    async def capture_button_click(e):
        if not dropdown.value:
            return

        progress_ring.visible = True
        countdown_text.visible = True
        results_area.visible = False
        page.update()

        cdp_info = await capture_and_parse(dropdown.value)

        progress_ring.visible = False
        countdown_text.visible = False
        results_column = results_area.content
        results_column.controls.clear()

        if not cdp_info:
            results_column.controls.append(ft.Text("No CDP packets captured. Make sure you're connected to a network with CDP-enabled devices."))
        else:
            card_content = ft.Column([
                ft.Text("CDP Packet Information", size=16, weight=ft.FontWeight.BOLD),
                *[ft.Text(f"{key}: {value}") for key, value in cdp_info.items()]
            ])
            result_card = ft.Container(
                content=card_content,
                padding=20,
                bgcolor=ft.colors.WHITE,
                border_radius=10,
                border=ft.border.all(1, ft.colors.GREY_400),
                width=350
            )
            results_column.controls.append(result_card)

        results_area.visible = True
        page.update()

    # Interface selection
    interfaces = get_windows_interfaces()
    dropdown = ft.Dropdown(
        width=300,
        options=[ft.dropdown.Option(iface) for iface in interfaces],
        label="Select Interface",
    )

    interface_container = ft.Container(
        content=ft.Column([
            ft.Text("Select Network Interface", size=16, weight=ft.FontWeight.BOLD),
            dropdown,
            ft.ElevatedButton("Capture CDP Packet", on_click=capture_button_click)
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        padding=20,
        bgcolor=ft.colors.WHITE,
        border_radius=10,
        border=ft.border.all(1, ft.colors.GREY_400),
        width=350,
        alignment=ft.alignment.center
    )

    # Main layout
    page.add(
        header,
        ft.Column([
            ft.Container(height=20),  # Added padding between header and interface container
            interface_container,
            progress_column,
            results_area
        ], alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    )

    # Function to update header width when the page resizes
    def page_resize(e):
        header.width = page.width
        page.update()

    # Set the resize event handler
    page.on_resize = page_resize

ft.app(target=main)