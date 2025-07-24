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

# History lists for last 5 used inputs
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
    output_dir =  os.path.join("/opt/xml/",output_dir_entry.get().strip())
    output_dir_name = output_dir_entry.get().strip()
    cve_output_name= cve_output_name_entry.get().strip()

    # Ensure targets and output directory are not empty
    if not targets:
        messagebox.showerror("Input Error", "Targets field cannot be empty.")
        return
    if not output_dir:
        messagebox.showerror("Input Error", "Output Directory field cannot be empty.")
        return

    if  cve_output_name=="":
        cve_output_name="output.json"
    if not cve_output_name.endswith('.json'):
        cve_output_name+='.json'
    cve_output = output_dir +"/"+"CVE_"+cve_output_name
    print(cve_output)
    # Collect selected options into a single quoted string
    selected_options = []
    if sV_var.get():
        print("svtrue")
        selected_options.append("-sV")
    if A_var.get():
        selected_options.append("-A")
    if O_var.get():
        selected_options.append("-O")
    print(selected_options)
    options_str = " ".join(f"'{opt}'" for opt in selected_options)
    print(options_str)
    timeout = timeout_entry.get()
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
    # Build command
    cmd = [sys.executable, "ingestor/rustIngestor.py"]
    if targets:
        cmd += targets.split()
    if output_dir:
        cmd += ["-o", output_dir]
    if options_str:
        cmd += ["--options", options_str]
    if timeout:
        cmd += ["--timeout", timeout]
    if use_top:
        cmd.append("--top")
    if ports:
        cmd += ["-p", ports]
    if nmapsn.get() :
        cmd.append("--nmap-host-discovery") 


    # Debug: print the command
    # print("Running command:", " ".join(cmd))
    print (cmd)
    result = subprocess.run(cmd)

    if result.returncode == 0:
        runcvecollector(output_dir,cve_output)
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

# GUI layout

# Initialize window
root = tk.Tk()
root.title("RustScan Ingestor GUI")
root.geometry("700x400")  # More compact size
# root.resizable(False, False)  # Prevent resizing

# Load and place background image
# bg_image = Image.open("nmapreport/static/img/bg.png")  # Replace with your file
# bg_photo = ImageTk.PhotoImage(bg_image)
# background_label = tk.Label(root, image=bg_photo)
# background_label.place(relwidth=1, relheight=1)

# Frame to hold widgets so they stay above background
frame = tk.Frame(root, bg="white", bd=2)
frame.place(relx=0.05, rely=0.08, relwidth=0.9, relheight=0.84)

# GUI Widgets
tk.Label(frame, text="Targets (space-separated):").grid(row=0, column=0, sticky="w")
target_entry = ttk.Combobox(frame, width=50, values=recent_targets)
target_entry.grid(row=0, column=1)

tk.Label(frame, text="Output Directory:").grid(row=1, column=0, sticky="w")
output_dir_entry = ttk.Combobox(frame, width=50, values=recent_output_dirs)
output_dir_entry.grid(row=1, column=1)



tk.Label(frame, text="Options:").grid(row=2, column=0, sticky="w")
sV_var = tk.BooleanVar(value=True)
A_var = tk.BooleanVar()
O_var = tk.BooleanVar()
tk.Checkbutton(frame, text="-sV", variable=sV_var).grid(row=2, column=1, sticky="w")
tk.Checkbutton(frame, text="-A", variable=A_var).grid(row=3, column=1, sticky="w")
tk.Checkbutton(frame, text="-O", variable=O_var).grid(row=4, column=1, sticky="w")


tk.Label(frame, text="Timeout (seconds):").grid(row=6, column=0, sticky="w")
timeout_entry = tk.Entry(frame)
timeout_entry.insert(0, "0")
timeout_entry.grid(row=6, column=1)

top_var = tk.BooleanVar()
tk.Checkbutton(frame, text="Use --top", variable=top_var).grid(row=7, column=1, sticky="w")

tk.Label(frame, text="Custom Ports:").grid(row=8, column=0, sticky="w")
ports_entry = tk.Entry(frame, width=50)
ports_entry.grid(row=8, column=1)

tk.Label(frame, text="cve Collector filename:").grid(row=9, column=0, sticky="w")
cve_output_name_entry = tk.Entry(frame, width=50)
cve_output_name_entry.grid(row=9, column=1)

nmapsn = tk.BooleanVar(value=True)
tk.Label(frame, text="nmap host-discovery:").grid(row=10, column=0, sticky="w")
tk.Checkbutton(frame, text="nmap -sn", variable=nmapsn).grid(row=10, column=1, sticky="w")


tk.Button(frame, text="Run", command=run_script).grid(row=11, column=1, pady=10)

root.mainloop()