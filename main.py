import ipaddress
import re
import shutil
import socket
import subprocess
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput


class NetworkToolUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(
            orientation="vertical",
            padding=20,
            spacing=15,
            **kwargs
        )

        self.add_widget(Label(
            text="ALL-IN-ONE NETWORK TOOL",
            font_size="22sp",
            bold=True,
            size_hint_y=0.1
        ))

        self.target_input = TextInput(
            hint_text="IP / Domain / Private network prefix (192.168.1)",
            multiline=False,
            font_size="16sp",
            size_hint_y=0.12
        )
        self.add_widget(self.target_input)

        button_layout = BoxLayout(
            orientation="horizontal",
            spacing=10,
            size_hint_y=0.12
        )

        port_button = Button(
            text="Port Scan",
            background_color=(0.1, 0.6, 0.9, 1)
        )
        port_button.bind(on_press=self.start_port_scan)

        ping_button = Button(
            text="Ping Sweep",
            background_color=(0.2, 0.8, 0.4, 1)
        )
        ping_button.bind(on_press=self.start_ping_sweep)

        dns_button = Button(
            text="Subdomains",
            background_color=(0.9, 0.5, 0.1, 1)
        )
        dns_button.bind(on_press=self.start_subdomain_scan)

        button_layout.add_widget(port_button)
        button_layout.add_widget(ping_button)
        button_layout.add_widget(dns_button)
        self.add_widget(button_layout)

        self.scroll = ScrollView(size_hint_y=0.66)
        self.output_label = Label(
            text="Results will appear here...",
            size_hint_y=None,
            halign="left",
            valign="top",
            font_size="14sp"
        )
        self.output_label.bind(texture_size=self._update_label_size)
        self.scroll.add_widget(self.output_label)
        self.add_widget(self.scroll)

    def _update_label_size(self, instance, texture_size):
        instance.size = (max(texture_size[0], self.scroll.width), texture_size[1])
        instance.text_size = (max(self.scroll.width - 20, 1), None)

    def update_output(self, message):
        def append_text(_dt):
            self.output_label.text += "\n" + message
            self.output_label.texture_update()
            self.scroll.scroll_y = 0
        Clock.schedule_once(append_text)

    def clear_output(self, title):
        self.output_label.text = f"--- {title} ---"
        self.output_label.texture_update()
        self.scroll.scroll_y = 1

    def show_error(self, message):
        self.output_label.text = message

    @staticmethod
    def valid_host(value):
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("Enter a valid IP address or domain name.")
        # Accept IPv4 or a conventional DNS hostname; reject URL paths/ports.
        try:
            return str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError:
            pass

        if len(value) > 253 or value.startswith(".") or value.endswith("."):
            raise ValueError("Enter a valid domain name without http:// or a path.")
        labels = value.split(".")
        if len(labels) < 2:
            raise ValueError("Enter a complete domain name, for example example.com.")
        for label in labels:
            if (not label or len(label) > 63 or
                    not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)):
                raise ValueError("The domain name format is invalid.")
        return value

    def start_port_scan(self, _instance):
        try:
            target = self.valid_host(self.target_input.text)
            # Resolve first so invalid/unreachable names produce a clear message.
            socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except (ValueError, socket.gaierror) as exc:
            self.show_error(str(exc) or "Could not resolve the target.")
            return

        self.clear_output(f"Checking common ports on {target}")
        threading.Thread(
            target=self.run_ports,
            args=(target,),
            daemon=True
        ).start()

    def run_ports(self, target):
        common_ports = (
            21, 22, 23, 25, 53, 80, 110, 143,
            443, 445, 3306, 3389, 8080
        )
        found = 0
        try:
            addresses = socket.getaddrinfo(
                target, None, family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )
            address = addresses[0][4][0]

            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.8)
                        if sock.connect_ex((address, port)) == 0:
                            found += 1
                            self.update_output(f"[+] TCP port {port}: OPEN")
                except OSError as exc:
                    self.update_output(f"[!] Port {port}: {exc}")

            if found == 0:
                self.update_output("No open ports found in the common-port list.")
            self.update_output("Check completed.")
        except socket.gaierror:
            self.update_output("Could not resolve the host name.")
        except OSError as exc:
            self.update_output(f"Network error: {exc}")

    def start_ping_sweep(self, _instance):
        prefix = self.target_input.text.strip()
        try:
            parts = prefix.split(".")
            if len(parts) != 3:
                raise ValueError
            network = ipaddress.ip_network(prefix + ".0/24", strict=False)
            if not network.is_private:
                self.show_error(
                    "For safety, Ping Sweep only accepts a private IPv4 "
                    "network prefix, e.g. 192.168.1"
                )
                return
        except ValueError:
            self.show_error(
                "Enter a valid private IPv4 prefix, e.g. 192.168.1"
            )
            return

        self.clear_output(f"Checking devices on {prefix}.0/24")
        threading.Thread(
            target=self.run_ping,
            args=(prefix,),
            daemon=True
        ).start()

    def run_ping(self, prefix):
        ping_path = shutil.which("ping")
        if not ping_path:
            self.update_output(
                "The ping command is not available on this Android device."
            )
            return

        found = 0
        for host in range(1, 255):
            ip = f"{prefix}.{host}"
            try:
                result = subprocess.run(
                    [ping_path, "-c", "1", "-W", "1", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                if result.returncode == 0:
                    found += 1
                    self.update_output(f"[+] Active device: {ip}")
            except (subprocess.TimeoutExpired, OSError):
                continue

        if found == 0:
            self.update_output("No responding devices found.")
        self.update_output("Ping check completed.")

    def start_subdomain_scan(self, _instance):
        try:
            domain = self.valid_host(self.target_input.text)
            # Subdomain lookup expects a domain, not a raw IP.
            socket.inet_aton(domain)
            raise ValueError("Enter a domain name, not an IP address.")
        except OSError:
            pass
        except ValueError as exc:
            self.show_error(str(exc))
            return

        self.clear_output(f"DNS lookups for {domain}")
        threading.Thread(
            target=self.run_subdomains,
            args=(domain,),
            daemon=True
        ).start()

    def run_subdomains(self, domain):
        # Basic DNS lookups only; use this only for domains you own or are
        # authorized to assess.
        subdomains = (
            "www", "mail", "ftp", "blog", "shop",
            "api", "dev", "admin", "portal"
        )
        found = 0
        for subdomain in subdomains:
            hostname = f"{subdomain}.{domain}"
            try:
                addresses = socket.getaddrinfo(
                    hostname, None, type=socket.SOCK_STREAM
                )
                ip = addresses[0][4][0]
                found += 1
                self.update_output(f"[+] {hostname} -> {ip}")
            except socket.gaierror:
                continue
            except OSError as exc:
                self.update_output(f"[!] {hostname}: {exc}")

        if found == 0:
            self.update_output("No matching DNS records found.")
        self.update_output("DNS lookup completed.")


class NetToolApp(App):
    def build(self):
        return NetworkToolUI()


if __name__ == "__main__":
    NetToolApp().run()
