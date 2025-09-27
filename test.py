import tkinter as tk
from tkinter import ttk
import threading
import time

# Simulated system modules
def run_auth():
    update_status("Auth", "Running")
    time.sleep(5)
    update_status("Auth", "Stopped")

def run_snort():
    update_status("Snort", "Running")
    time.sleep(5)
    update_status("Snort", "Stopped")

def run_ufw():
    update_status("UFW", "Running")
    time.sleep(5)
    update_status("UFW", "Stopped")

def run_analyzer():
    update_status("Analyzer", "Running")
    time.sleep(5)
    update_status("Analyzer", "Stopped")

# GUI setup
root = tk.Tk()
root.title("SOC Thread Dashboard")

status_labels = {}

def update_status(system, status):
    status_labels[system].config(text=f"Status: {status}")

def start_thread(system, target):
    update_status(system, "Starting...")
    threading.Thread(target=target).start()

def stop_thread(system):
    update_status(system, "Stopped (manual)")

systems = {
    "Auth": run_auth,
    "Snort": run_snort,
    "UFW": run_ufw,
    "Analyzer": run_analyzer
}

for i, (name, func) in enumerate(systems.items()):
    frame = ttk.LabelFrame(root, text=name)
    frame.grid(row=i, column=0, padx=10, pady=5, sticky="ew")

    status = ttk.Label(frame, text="Status: Idle")
    status.grid(row=0, column=0, padx=5)
    status_labels[name] = status

    start_btn = ttk.Button(frame, text="Start", command=lambda n=name, f=func: start_thread(n, f))
    start_btn.grid(row=0, column=1, padx=5)

    stop_btn = ttk.Button(frame, text="Stop", command=lambda n=name: stop_thread(n))
    stop_btn.grid(row=0, column=2, padx=5)

root.mainloop()