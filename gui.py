#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk  # type: ignore # Pillow library
import subprocess
import sys
import time
import json
import os
from ingestor.cvecollector import *
from nmapreport import  get_ip_and_cidr


HISTORY_FILE = "input_history.json"

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                data = json.load(f)
                return data.get("targets", []), data.get("output_dirs", [])
        except Exception:
            pass
    return [], []

def save_history(targets, output_dirs):
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump({"targets": targets, "output_dirs": output_dirs}, f)
    except Exception:
        pass


recent_targets, recent_output_dirs = load_history()

def update_history(history_list, value):
    if value in history_list:
        history_list.remove(value)
    history_list.insert(0, value)
    if len(history_list) > 5:
        history_list.pop()

def run_script():
    start_time = time.time()
    targets = target_entry.get().strip()
    output_dir_input = output_dir_entry.get().strip()
    if not targets:     
        messagebox.showerror("Input Error", "Targets field cannot be empty.")
        return
    if not output_dir_input:
        messagebox.showerror("Input Error", "Output Directory field cannot be empty.")
        return
    
    output_dir_clean = output_dir_input.strip("/").replace("../", "").replace("..\\", "")
    output_dir_clean = output_dir_clean.replace("opt/xml/", "").replace("opt\\xml\\", "")
    output_dir = os.path.join("/opt/xml", output_dir_clean)
    output_dir_name = output_dir_clean

    cve_output_name = cve_output_name_entry.get().strip()
    if  cve_output_name=="":
        cve_output_name = targets.replace("/", "_")
    if not cve_output_name.endswith('.json'):
        cve_output_name+='.json'
    cve_output = output_dir +"/"+"CVE_"+cve_output_name
    print(cve_output)
    
    selected_options = []
    if sV_var.get():
        selected_options.append("-sV")
    if sS_var.get():
        selected_options.append("-sS")
    if sT_var.get():
        selected_options.append("-sT")
    if sU_var.get():
        selected_options.append("-sU")
    if A_var.get():
        selected_options.append("-A")
    if O_var.get():
        selected_options.append("-O")
    if Pn_var.get():
        selected_options.append("-Pn")
    if T4_var.get():
        selected_options.append("-T4")
    print(selected_options)
    options_str = " ".join(f"'{opt}'" for opt in selected_options)
    print(options_str)
    ports = ports_entry.get().strip()
    use_top = top_var.get()

    if ports and use_top:
        messagebox.showerror("Error", "You cannot use both --top and --ports at the same time.")
        return

    if nmapsn.get():
        print(nmapsn.get())
        targets_list = targets.split()
        for t in targets_list:
            if '/' not in t:
                print(t)
                messagebox.showerror("Error", f"--nmap-host-discovery requires CIDR notation, but {t} is not a CIDR (e.g., /24)")
                return
    
    
    cmd = [sys.executable, "ingestor/rustIngestor.py"]
    if targets:
        cmd += targets.split()
    if output_dir:
        cmd += ["-o", output_dir]
    if options_str:
        cmd += ["--options", options_str]
    if use_top:
        cmd.append("--top")
    if ports:
        cmd += ["-p", ports]
    if nmapsn.get() :
        cmd.append("--nmap-host-discovery") 


    
    print (cmd)
    result = subprocess.run(cmd)

    if result.returncode == 0:
        # Create scan options dictionary
        scan_options = {
            "target_settings": {
                "targets": targets,
                "nmap_host_discovery": nmapsn.get()
            },
            "scan_options": {
                "sV": sV_var.get(),
                "sS": sS_var.get(),
                "sT": sT_var.get(),
                "sU": sU_var.get(),
                "A": A_var.get(),
                "O": O_var.get(),
                "Pn": Pn_var.get(),
                "T4": T4_var.get()
            },
            "port_settings": {
                "use_top_ports": top_var.get(),
                "custom_ports": ports_entry.get().strip()
            },
            "command": " ".join(cmd)
        }
        runcvecollector(output_dir, cve_output, scan_options)
        elapsed = time.time() - start_time
        print(f"[+] All tasks completed in {elapsed:.2f} seconds.")
        messagebox.showinfo("Done", f"All tasks completed in {elapsed:.2f} seconds.")
        # Update history for targets and output_dir
        update_history(recent_targets, targets)
        update_history(recent_output_dirs, output_dir_name)
        target_entry['values'] = recent_targets
        output_dir_entry['values'] = recent_output_dirs
        save_history(recent_targets, recent_output_dirs)
    else:
        messagebox.showerror("Error", f"Script failed with return code {result.returncode}")




root = tk.Tk()
root.title("RustScan Ingestor GUI")
root.geometry("900x600")  # Larger size to accommodate all options

# Set the icon icon
try:
    icon_path = "nmapreport/static/logomin.png"
    if os.path.exists(icon_path):
        icon = ImageTk.PhotoImage(Image.open(icon_path))
        root.iconphoto(True, icon)
except Exception as e:
    print(f"Could not load icon: {e}")


root.minsize(600, 400)
root.configure(bg='#f0f0f0')  

# Configure to expand properly
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

#main container frame
container = tk.Frame(root)
container.pack(fill="both", expand=True)

#scrollbar
canvas = tk.Canvas(container, bg='#f0f0f0')
scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas, bg="#ffffff", bd=2, relief=tk.GROOVE)


scrollable_frame.grid_columnconfigure(1, weight=1)
scrollable_frame.grid_columnconfigure(2, weight=1)

# Configure the canvas
canvas.configure(yscrollcommand=scrollbar.set)
canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))


scrollbar.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True, padx=20, pady=20)


scrollable_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.bind('<Configure>', lambda e: canvas.itemconfig(canvas_frame, width=e.width-40))


canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")


def configure_scroll_region(event):
    canvas.configure(scrollregion=canvas.bbox("all"))

def configure_frame_width(event):
    canvas.itemconfig(canvas_frame, width=event.width)  # 40 is for padding


scrollable_frame.bind("<Configure>", configure_scroll_region)
canvas.bind("<Configure>", configure_frame_width)


def on_mousewheel(event):
    if event.num == 5 or event.delta < 0:
        canvas.yview_scroll(1, "units")
    elif event.num == 4 or event.delta > 0:
        canvas.yview_scroll(-1, "units")


canvas.bind_all("<MouseWheel>", on_mousewheel)  # Windows and MacOS
canvas.bind_all("<Button-4>", on_mousewheel)    # Linux
canvas.bind_all("<Button-5>", on_mousewheel)    # Linux


scrollbar.bind("<MouseWheel>", on_mousewheel)
scrollbar.bind("<Button-4>", on_mousewheel)
scrollbar.bind("<Button-5>", on_mousewheel)


frame = scrollable_frame


padding = {'padx': 10, 'pady': 5}

# Title label
title_label = tk.Label(frame, text="RustScan Ingestor", font=('Helvetica', 16, 'bold'), bg="#ffffff")
title_label.grid(row=0, column=0, columnspan=3, pady=15)


# Create targets frame
targets_frame = tk.LabelFrame(frame, text="Target Settings", bg="#ffffff", padx=10, pady=5)
targets_frame.grid(row=1, column=0, columnspan=3, sticky="ew", **padding)

# Target input
tk.Label(targets_frame, text="Targets (space-separated):", bg="#ffffff").grid(row=0, column=0, sticky="w", **padding)
target_entry = ttk.Combobox(targets_frame, width=70, values=recent_targets)
cidr = get_ip_and_cidr.get_local_cidr()
if cidr:
    placeholder = cidr
else:
    placeholder="192.168.1.0/24"
    
target_entry.insert(0, placeholder)

def on_target_entry_focus_in(event):
    if target_entry.get() == placeholder:
        target_entry.delete(0, tk.END)
        
def on_target_entry_focus_out(event):
    if not target_entry.get():
        target_entry.insert(0, placeholder)

target_entry.bind('<FocusIn>', on_target_entry_focus_in)
target_entry.bind('<FocusOut>', on_target_entry_focus_out)
target_entry.grid(row=0, column=1, columnspan=2, sticky="ew", **padding)

# Host discovery option in targets frame
nmapsn = tk.BooleanVar(value=True)
tk.Checkbutton(targets_frame, text="Use nmap host discovery (-sn)", variable=nmapsn, bg="#ffffff").grid(row=1, column=0, columnspan=3, sticky="w", **padding)

tk.Label(targets_frame, text="Output Directory:", bg="#ffffff").grid(row=2, column=0, sticky="w", **padding)
output_dir_entry = ttk.Combobox(targets_frame, width=70, values=recent_output_dirs)
output_dir_entry.grid(row=2, column=1, columnspan=2, sticky="ew", **padding)


ttk.Separator(frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky="ew", pady=10)

# Scan Options section with a frame
options_frame = tk.LabelFrame(frame, text="Scan Options", bg="#ffffff", padx=10, pady=5)
options_frame.grid(row=4, column=0, columnspan=3, sticky="ew", **padding)

# Create variables for checkboxes
sV_var = tk.BooleanVar(value=True)  # Version detection
sS_var = tk.BooleanVar()  
sT_var = tk.BooleanVar()  
sU_var = tk.BooleanVar()  
A_var = tk.BooleanVar()   
O_var = tk.BooleanVar()   
Pn_var = tk.BooleanVar()  
T4_var = tk.BooleanVar()  

# Create and position checkboxes in two columns inside options_frame
tk.Checkbutton(options_frame, text="-sV (Version detection)", variable=sV_var, bg="#ffffff").grid(row=0, column=0, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-sS (SYN scan)", variable=sS_var, bg="#ffffff").grid(row=1, column=0, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-sT (TCP connect scan)", variable=sT_var, bg="#ffffff").grid(row=2, column=0, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-sU (UDP scan)", variable=sU_var, bg="#ffffff").grid(row=3, column=0, sticky="w", padx=5)

tk.Checkbutton(options_frame, text="-A (Aggressive scan)", variable=A_var, bg="#ffffff").grid(row=0, column=1, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-O (OS detection)", variable=O_var, bg="#ffffff").grid(row=1, column=1, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-Pn (No ping)", variable=Pn_var, bg="#ffffff").grid(row=2, column=1, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-T4 (Aggressive timing)", variable=T4_var, bg="#ffffff").grid(row=3, column=1, sticky="w", padx=5)


# Additional options frame
additional_frame = tk.LabelFrame(frame, text="Ports Settings", bg="#ffffff", padx=10, pady=5)
additional_frame.grid(row=5, column=0, columnspan=3, sticky="ew", **padding)

# Top ports settings
top_var = tk.BooleanVar()
tk.Checkbutton(additional_frame, text="Use Top Ports", variable=top_var, bg="#ffffff").grid(row=0, column=0, sticky="w", **padding)

# Custom ports
tk.Label(additional_frame, text="Custom Ports:", bg="#ffffff").grid(row=1, column=0, sticky="w", **padding)
ports_entry = tk.Entry(additional_frame, width=50)
ports_entry.grid(row=1, column=1, columnspan=2, sticky="ew", **padding)

""" uncomment to choose cve output file name"""
# CVE settings frame
# cve_frame = tk.LabelFrame(frame, text="CVE Settings", bg="#ffffff", padx=10, pady=5)
# cve_frame.grid(row=6, column=0, columnspan=3, sticky="ew", **padding)

# tk.Label(cve_frame, text="CVE Collector filename:", bg="#ffffff").grid(row=0, column=0, sticky="w", **padding)
cve_output_name_entry = tk.Entry(frame, width=50)
# cve_output_name_entry.grid(row=0, column=1, columnspan=2, sticky="ew", **padding)
cve_output_name_entry.insert(0, "")

# Run button with styling
run_button = tk.Button(frame, text="Run Scan", command=run_script, 
                      bg="#4CAF50", fg="white", 
                      font=('Helvetica', 12, 'bold'),
                      padx=20, pady=10)
run_button.grid(row=7, column=0, columnspan=3, pady=20)

root.mainloop()