import flet as ft
from network.interface import get_windows_interfaces, get_active_interface
from network.cdp_capture import capture_and_parse_cdp
from utils.logger import logger


class CDPDiscoveryApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.setup_page()
        self.create_ui_elements()
        self.layout_ui()

    def setup_page(self):
        self.page.title = "Link Discovery Tool"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 0
        self.page.spacing = 0
        self.page.vertical_alignment = ft.MainAxisAlignment.START
        self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        self.page.window.height = 425
        self.page.window.width = 540
        self.page.on_resized = lambda e: print(f"Window resized to W{self.page.window.width}xH{self.page.window.height}")

    def create_ui_elements(self):
        self.dropdown = ft.Dropdown(
            width=300,
            options=[ft.dropdown.Option(iface) for iface in get_windows_interfaces()],
            label="Select Interface",
            value=get_active_interface()
        )
        self.discovery_protocol_checkbox = ft.Row([
            ft.Checkbox(label="CDP", value=True), 
            ft.Checkbox(label="LLDP", value=False)
        ], alignment=ft.MainAxisAlignment.CENTER)
        self.capture_button = ft.ElevatedButton("Capture Discovery Packet", on_click=self.capture_button_click)
        self.progress_ring = ft.ProgressRing(visible=False)
        self.countdown_text = ft.Text("Waiting for discovery packets... (max 60 seconds)", visible=False)
        self.results_area = ft.Container(
            content=ft.Column(spacing=10),
            visible=False
        )

    def layout_ui(self):
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
            alignment=ft.alignment.center
        )
        
        progress_column = ft.Column([
            self.progress_ring,
            self.countdown_text
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER)

        self.page.appbar = ft.AppBar(
            toolbar_height=60,
            title=ft.Text("Link Discover", color=ft.colors.WHITE, weight=ft.FontWeight.BOLD),
            center_title=False,
            bgcolor=ft.colors.BLACK,
        )

        self.page.add(
            ft.Column([
                ft.Container(height=20),
                interface_container,
                progress_column,
                self.results_area
            ], alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
        )

    async def capture_button_click(self, e):
        if not self.dropdown.value:
            return

        self.capture_button.disabled = True
        self.progress_ring.visible = True
        self.countdown_text.visible = True
        self.results_area.visible = False
        self.page.update()

        cdp_info = None
        async for remaining_time in capture_and_parse_cdp(self.dropdown.value):
            self.countdown_text.value = f"Waiting for CDP packet... ({remaining_time} seconds remaining)"
            self.page.update()
            if isinstance(remaining_time, dict):  # This means we got CDP info
                cdp_info = remaining_time
                break

        self.progress_ring.visible = False
        self.countdown_text.visible = False
        results_column = self.results_area.content
        results_column.controls.clear()

        if not cdp_info:
            error_card = ft.Container(
                content=ft.Column([
                    ft.Text("Error", size=16, weight=ft.FontWeight.BOLD),
                    ft.Text("No CDP packets captured. Make sure you're connected to a network with CDP-enabled devices.")
                ]),
                padding=20,
                bgcolor=ft.colors.WHITE,
                border_radius=10,
                border=ft.border.all(1, ft.colors.GREY_400),
                width=350
            )
            self.page.window.height = 530
            results_column.controls.append(error_card)
        else:
            card_content = ft.Column([
                ft.Text("CDP Packet Information", size=16, weight=ft.FontWeight.BOLD),
                *[ft.Markdown(f"**{key}:** {value}", selectable=True) for key, value in cdp_info.items()]
            ])
            
            result_card = ft.Container(
                content=card_content,
                padding=20,
                bgcolor=ft.colors.WHITE,
                border_radius=10,
                border=ft.border.all(1, ft.colors.GREY_400),
                width=350
            )
            self.page.window.height = 890
            results_column.controls.append(result_card)

        self.capture_button.disabled = False
        self.results_area.visible = True
        self.page.update()
        