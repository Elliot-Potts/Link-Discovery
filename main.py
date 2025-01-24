"""Main module/entry-point for the Link Discovery Tool."""

import flet as ft
from ui.app import DiscoveryApp

if __name__ == "__main__":
    ft.app(target=DiscoveryApp, assets_dir="assets")
