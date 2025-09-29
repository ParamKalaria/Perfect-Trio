import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
from datetime import datetime
import os
import sqlite3
import subprocess

root = tk.Tk()
root.title("SOC Thread Dashboard")

status_labels = {}
running_labels = {}
last_labels = {}
start_times = {}
last_durations = {}

# Thread control
def update_status(system, status):
    status_labels[system].config(text=f"Status: {status}")

def update_running_time(system):
    while system in start_times:
        elapsed = datetime.now() - start_times[system]
        running_labels[system].config(text=f"Running Time: {str(elapsed).split('.')[0]}")
        time.sleep(1)

def start_thread(system, target):
    start_times[system] = datetime.now()
    update_status(system, "Running")
    threading.Thread(target=target).start()
    threading.Thread(target=update_running_time, args=(system,), daemon=True).start()

def stop_thread(system):
    if system in start_times:
        duration = datetime.now() - start_times[system]
        last_durations[system] = duration
        last_labels[system].config(text=f"Last Run: {str(duration).split('.')[0]}")
        del start_times[system]
    update_status(system, "Stopped")

# Simulated system modules
def run_auth(): time.sleep(5); stop_thread("Auth")
def run_snort(): time.sleep(5); stop_thread("Snort")
def run_ufw(): time.sleep(5); stop_thread("UFW")
def run_analyzer(): time.sleep(5); stop_thread("Analyzer")

systems = {
    "Auth": run_auth,
    "Snort": run_snort,
    "UFW": run_ufw,
    "Analyzer": run_analyzer
}

# Layout
for i, (name, func) in enumerate(systems.items()):
    frame = ttk.LabelFrame(root, text=name)
    frame.grid(row=i, column=0, padx=10, pady=5, sticky="ew")

    status = ttk.Label(frame, text="Status: Idle")
    status.grid(row=0, column=0, padx=5)
    status_labels[name] = status

    running = ttk.Label(frame, text="Running Time: 00:00:00")
    running.grid(row=1, column=0, padx=5)
    running_labels[name] = running

    last = ttk.Label(frame, text="Last Run: --")
    last.grid(row=2, column=0, padx=5)
    last_labels[name] = last

    start_btn = ttk.Button(frame, text="Start", command=lambda n=name, f=func: start_thread(n, f))
    start_btn.grid(row=0, column=1, padx=5)

    stop_btn = ttk.Button(frame, text="Stop", command=lambda n=name: stop_thread(n))
    stop_btn.grid(row=0, column=2, padx=5)

# Menu bar
def show_about():
    messagebox.showinfo("About", "SOC Thread Dashboard\nVersion 1.0\nBuilt by Param Kalaria")

def show_help():
    messagebox.showinfo("Help", "Start or stop each system thread.\nMonitor status and runtime.\nUse Options for analysis, logs, and DB.")

def refresh_all():
    for system in systems:
        update_status(system, "Idle")
        running_labels[system].config(text="Running Time: 00:00:00")
        last_labels[system].config(text="Last Run: --")
        if system in start_times:
            del start_times[system]

def trigger_analyze():
    start_thread("Analyzer", run_analyzer)

def set_custom_timer():
    interval = simpledialog.askinteger("Set Timer", "Enter interval in minutes:", minvalue=1, maxvalue=1440)
    if interval:
        messagebox.showinfo("Timer Set", f"Custom timer set to {interval} minutes.\n(Implement scheduling logic separately)")

def open_logs():
    log_path = "logs/activity.log"
    if os.path.exists(log_path):
        subprocess.Popen(["notepad", log_path])
    else:
        messagebox.showerror("Error", "Log file not found.")

def open_db():
    db_path = "db/threat_analysis/threats.db"
    if os.path.exists(db_path):
        subprocess.Popen(["notepad", db_path])
    else:
        messagebox.showerror("Error", "Database file not found.")

menu_bar = tk.Menu(root)

options_menu = tk.Menu(menu_bar, tearoff=0)
options_menu.add_command(label="Analyze", command=trigger_analyze)
options_menu.add_command(label="Set Custom Timer", command=set_custom_timer)
options_menu.add_command(label="Activity Logs", command=open_logs)
options_menu.add_command(label="DB", command=open_db)
options_menu.add_separator()
options_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="Options", menu=options_menu)

help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="Help", command=show_help)
help_menu.add_command(label="About", command=show_about)
menu_bar.add_cascade(label="Help", menu=help_menu)

root.config(menu=menu_bar)
root.mainloop()