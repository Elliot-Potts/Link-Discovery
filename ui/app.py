"""UI module logic for the Link Discovery Tool."""

import flet as ft
from network.interface import get_windows_interfaces, get_active_interface
from network.packet_capture import capture_and_parse_packets
from utils.logger import logger

class DiscoveryApp:
    """
    Main class for the Link Discovery Tool.
    """
    def __init__(self, page: ft.Page):
        self.page = page
        self.setup_page()
        self.create_ui_elements()
        self.layout_ui()

    def setup_page(self):
        """
        Setup the page.
        """
        self.page.title = "Link Discovery Tool"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 0
        self.page.spacing = 0
        self.page.vertical_alignment = ft.MainAxisAlignment.START
        self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        self.page.window.height = 355
        self.page.window.width = 540
        self.page.window.min_height = 355
        self.page.window.min_width = 540
        self.page.scroll = ft.ScrollMode.ALWAYS
        self.page.on_resized = lambda e: print(f"Window resized to W{self.page.window.width}xH{self.page.window.height}")

    def create_ui_elements(self):
        """
        Create the UI elements.
        """
        self.dropdown = ft.Dropdown(
            width=300,
            options=[ft.dropdown.Option(iface) for iface in get_windows_interfaces()],
            label="Select Interface",
            value=get_active_interface()
        )
        self.cdp_checkbox = ft.Checkbox(label="CDP", value=True)
        self.lldp_checkbox = ft.Checkbox(label="LLDP", value=True)
        self.discovery_protocol_checkbox = ft.Row([
            self.cdp_checkbox,
            self.lldp_checkbox
        ], alignment=ft.MainAxisAlignment.CENTER)
        self.capture_button = ft.ElevatedButton("Capture Discovery Packet", on_click=self.capture_button_click)
        self.progress_ring = ft.ProgressRing(visible=False)
        self.countdown_text = ft.Text("Waiting for discovery packets... (max 60 seconds)", visible=False)
        self.results_area = ft.Container(
            content=ft.Row(spacing=10, alignment=ft.MainAxisAlignment.CENTER, vertical_alignment=ft.CrossAxisAlignment.START),
            visible=False,
            margin=ft.margin.only(bottom=20)
        )

    def layout_ui(self):
        """
        Layout the UI elements.
        """
        interface_container = ft.Container(
            content=ft.Column([
                ft.Text("Select Network Interface", size=16, weight=ft.FontWeight.BOLD),
                self.dropdown,
                self.discovery_protocol_checkbox,
                self.capture_button
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            padding=20,
            bgcolor=ft.colors.WHITE,
            border_radius=10,
            border=ft.border.all(1, ft.colors.GREY_400),
            width=350,
            margin=ft.margin.only(top=20),
            alignment=ft.alignment.center
        )

        self.progress_column = ft.Container(
            content=ft.Column([
                self.progress_ring,
                self.countdown_text
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            margin=ft.margin.all(20),
        )

        self.page.appbar = ft.AppBar(
            toolbar_height=60,
            title=ft.Text("Link Discovery", color=ft.colors.WHITE, weight=ft.FontWeight.BOLD),
            center_title=False,
            bgcolor=ft.colors.BLACK,
        )

        self.page.add(
            ft.Column([
                interface_container,
                self.progress_column,
                self.results_area
            ], alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10, scroll=ft.ScrollMode.ALWAYS)
        )

    def create_info_card(self, title, info_dict=None, error_message=None):
        """
        Create a generic info card.
        """
        if info_dict:
            card_content = ft.Column([
                ft.Text(title, size=16, weight=ft.FontWeight.BOLD),
                *[ft.Markdown(f"**{key}:** {value}", selectable=True) for key, value in info_dict.items()]
            ])
        else:
            card_content = ft.Column([
                ft.Text("Error", size=16, weight=ft.FontWeight.BOLD),
                ft.Text(error_message)
            ])

        return ft.Container(
            content=card_content,
            padding=20,
            bgcolor=ft.colors.WHITE,
            border_radius=10,
            border=ft.border.all(1, ft.colors.GREY_400),
            width=350
        )

    async def capture_button_click(self):
        """
        Handle request to capture discovery packets.
        """
        if not self.dropdown.value:
            return

        protocols = []
        if self.cdp_checkbox.value:
            protocols.append("CDP")
        if self.lldp_checkbox.value:
            protocols.append("LLDP")

        if not protocols:
            return

        self.page.window.height = 480
        self.capture_button.disabled = True
        self.progress_column.margin = ft.margin.all(20)
        self.progress_ring.visible = True
        self.countdown_text.visible = True
        self.results_area.visible = True
        results_column = self.results_area.content
        results_column.controls.clear()
        self.page.update()

        results = {}
        async for result in capture_and_parse_packets(self.dropdown.value, protocols):
            if isinstance(result, dict):
                # Update the results dictionary with the new protocol information
                results.update(result)
                # Extract protocol from the result dictionary
                protocol = next(iter(result))
                info = result[protocol]
                result_card = self.create_info_card(f"{protocol} Packet Information", info)
                results_column.controls.append(result_card)

                if protocol == "CDP":
                    logger.debug("Setting window height for CDP info.")
                    self.page.window.height = 950
                elif protocol == "LLDP" and self.page.window.height < 790:
                    logger.debug("Setting window height for LLDP info.")
                    self.page.window.height = 920

                self.page.update()
            elif isinstance(result, int):
                self.countdown_text.value = f"Waiting for discovery packets... ({result} seconds remaining)"
                self.page.update()

        # Increase the window width to accommodate multiple protocol cards
        if len(results.keys()) > 1:
            self.page.window.width = 780

        self.progress_column.margin = ft.margin.only(0)
        self.progress_ring.visible = False
        self.countdown_text.visible = False

        if not results:
            error_card = self.create_info_card(
                title="Error",
                error_message="No discovery packets captured. Make sure you're connected to a network with CDP/LLDP-enabled devices."
            )
            self.page.window.height = 560
            results_column.controls.append(error_card)

        self.capture_button.disabled = False
        self.page.update()
