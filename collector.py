# collector. py describes the collection of data from the user. 

import subprocess # subprocess to read the output from the command "netsh wlan show interfaces" in powershell
from analyzer import UserConfig # uses UserConfig class from analyzer

# Runs the command and returns the output
def run_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""
    except FileNotFoundError:
        return ""

# Based on the output of the command, returns the Encryption standard
def define_encryption(security: str) -> str:
    security = security.strip().upper()
    if "WPA3" in security:
        return "WPA3"
    if "WPA2" in security:
        return "WPA2"
    if security in ["WPA1", "WPA"]:
        return "WPA"
    if "WEP" in security:
        return "WEP"
    if security in ["", "--", "NONE", "OPEN"]:
        return "OPEN"

    return "UNKNOWN"

# describes what cipher is being used by the wireless network from the output of the command
def define_cipher(cipher_text: str) -> str:
    cipher_text = cipher_text.strip().upper()

    if "CCMP" in cipher_text:
        return "CCMP"
    if "AES" in cipher_text:
        return "AES"
    if "TKIP" in cipher_text:
        return "TKIP"
    if cipher_text in ["NONE", "OPEN"]:
        return "NONE"

    return "UNKNOWN"

# describes the authentication type in use (personal or enterprise)
def define_authentication(security: str) -> str:
    security = security.strip().upper()

    if "802.1X" in security or "ENTERPRISE" in security:
        return "ENTERPRISE"
    if "PERSONAL" in security or "WPA" in security or "WEP" in security or "OPEN" in security:
        return "PERSONAL"

    return "UNKNOWN"

# uses a dictionary to parse the output. Cleaning
def parse_active_config(output: str) -> dict:
    info = {
        "ssid": "UNKNOWN",
        "encryption": "UNKNOWN",
        "cipher": "UNKNOWN",
        "authentication": "UNKNOWN",
        "wps": False,
    }

    if not output:
        return info

    connected = False

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("State"):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip().lower() == "connected":
                connected = True

        elif line.startswith("SSID") and not line.startswith("BSSID"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                ssid = parts[1].strip()
                if ssid:
                    info["ssid"] = ssid

        elif line.startswith("Authentication"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                auth_text = parts[1].strip()
                info["encryption"] = define_encryption(auth_text)
                info["authentication"] = define_authentication(auth_text)

        elif line.startswith("Cipher"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                cipher_text = parts[1].strip()
                info["cipher"] = define_cipher(cipher_text)

    if not connected:
        return {
            "ssid": "UNKNOWN",
            "encryption": "UNKNOWN",
            "cipher": "UNKNOWN",
            "authentication": "UNKNOWN",
            "wps": False,
        }

    return info

# Get the current config, run the command and clean the output
def get_active_config() -> UserConfig:
    output = run_command(["netsh", "wlan", "show", "interfaces"])
    data = parse_active_config(output)

    return UserConfig(
        ssid=data["ssid"],
        encryption_standard=data["encryption"],
        cipher=data["cipher"],
        authentication_type=data["authentication"],
        wps=data["wps"],
    )
