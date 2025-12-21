import json
import os
import subprocess
import etw

TI_GUID = etw.GUID("{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}")       # Microsoft-Windows-Threat-Intelligence
AUDIT_GUID = etw.GUID("{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23}")    # Microsoft-Windows-Kernel-Audit-API-Calls

def on_event(evt):
    try:
        # Event is a tuple: (event_id, data_dict)
        event_id = evt[0]
        data = evt[1]

        task_name = data.get('Task Name', 'Unknown')

        # Print ALL events to see what we're actually getting
        print(f"Event ID: {event_id}, Task: {task_name}")

        # Also try to print read/write events with all available data
        if event_id in (10, 11):
            print(f"!!! FOUND READ/WRITE EVENT !!!")
            print(f"Full data: {data}")

    except Exception as exc:
        print(f"Error parsing event: {exc}")

def enable_threat_intelligence_channel():
    """Enable the Threat-Intelligence Analytic channel."""
    try:
        # First check if it's already enabled
        print("[*] Checking Threat-Intelligence Analytic channel status...")
        result = subprocess.run(
            ["wevtutil", "gl", "Microsoft-Windows-Threat-Intelligence/Analytic"],
            capture_output=True,
            text=True,
            check=False
        )

        if "enabled: true" in result.stdout.lower():
            print("[+] Threat-Intelligence Analytic channel is already enabled")
            return

        print("[*] Attempting to enable Threat-Intelligence Analytic channel...")
        result = subprocess.run(
            ["wevtutil", "sl", "Microsoft-Windows-Threat-Intelligence/Analytic", "/e:true"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            print("[+] Threat-Intelligence Analytic channel enabled")
        else:
            print(f"[!] Warning: Could not enable channel: {result.stderr.strip()}")
            print("[!] Note: This provider may require Windows Defender ATP/MDE to be active")
            print("[!] Continuing anyway - ETW session will start but may not receive events")
    except Exception as exc:
        print(f"[!] Error checking/enabling channel: {exc}")

def main():
    pid = os.getpid()
    print(f"[etw-consumer] pid={pid}")

    # Enable the TI Analytic channel
    enable_threat_intelligence_channel()

    input("[etw-consumer] press Enter to start consuming ETW events...")

    providers = [
        etw.ProviderInfo("Microsoft-Windows-Threat-Intelligence", TI_GUID),
    ]

    with etw.ETW(providers=providers, event_callback=on_event):
        etw.run("etw")

if __name__ == "__main__":
    main()
