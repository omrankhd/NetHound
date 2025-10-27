#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk  # type: ignore # Pillow library
import subprocess
import sys
import time
import json
import os
import threading
from queue import Queue, Empty
from ingestor.cvecollector import *
from nethoundreport import get_ip_and_cidr


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

# Thread-safe queue for GUI updates
output_queue = Queue()

def append_output_safe(text, tag=None):
    """Thread-safe function to queue output for GUI update"""
    output_queue.put((text, tag))

def process_output_queue():
    """Process queued output updates in the main GUI thread"""
    try:
        while True:
            try:
                text, tag = output_queue.get_nowait()
                output_text.config(state='normal')
                if tag:
                    output_text.insert(tk.END, text, tag)
                else:
                    output_text.insert(tk.END, text)
                output_text.see(tk.END)
                output_text.config(state='disabled')
            except Empty:
                break
    except Exception as e:
        print(f"Error processing output queue: {e}")
    
    # Schedule next check
    root.after(100, process_output_queue)

def append_output(text, tag=None):
    """Append text to the output box (main thread only)"""
    output_text.config(state='normal')
    if tag:
        output_text.insert(tk.END, text, tag)
    else:
        output_text.insert(tk.END, text)
    output_text.see(tk.END)
    output_text.config(state='disabled')

def clear_output():
    """Clear the output box"""
    output_text.config(state='normal')
    output_text.delete(1.0, tk.END)
    output_text.config(state='disabled')

def run_script_thread():
    """Run the script in a separate thread to avoid blocking the GUI"""
    thread = threading.Thread(target=run_script, daemon=True)
    thread.start()

def run_script():
    start_time = time.time()
    
    # Disable run button during execution (thread-safe)
    root.after(0, lambda: run_button.config(state='disabled', text='Running...'))
    root.after(0, clear_output)
    
    targets = target_entry.get().strip()
    output_dir_input = output_dir_entry.get().strip()
    
    if not targets:     
        root.after(0, lambda: messagebox.showerror("Input Error", "Targets field cannot be empty."))
        root.after(0, lambda: run_button.config(state='normal', text='Run Scan'))
        return
    if not output_dir_input:
        root.after(0, lambda: messagebox.showerror("Input Error", "Output Directory field cannot be empty."))
        root.after(0, lambda: run_button.config(state='normal', text='Run Scan'))
        return
    
    # Clean output directory
    output_dir_clean = output_dir_input.strip("/").replace("../", "").replace("..\\", "")
    output_dir_clean = output_dir_clean.replace("opt/xml/", "").replace("opt\\xml\\", "")
    output_dir_clean = output_dir_clean.replace(" ", "_") 
    output_dir = os.path.join("/opt/xml", output_dir_clean)
    output_dir_name = output_dir_clean

    cve_output_name = cve_output_name_entry.get().strip()
    if cve_output_name == "":
        cve_output_name = targets.replace("/", "_")
    if not cve_output_name.endswith('.json'):
        cve_output_name += '.json'
    cve_output = output_dir + "/" + "CVE_" + cve_output_name
    
    # Collect selected options
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
    
    options_str = " ".join(f"'{opt}'" for opt in selected_options)
    
    # Clean ports
    clean_ports = ports_entry.get().strip().replace(' ', ',')
    while ',,' in clean_ports:
        clean_ports = clean_ports.replace(',,', ',')
    ports = clean_ports.strip(',')
    use_top = top_var.get()

    if ports and use_top:
        root.after(0, lambda: messagebox.showerror("Error", "You cannot use both --top and --ports at the same time."))
        root.after(0, lambda: run_button.config(state='normal', text='Run Scan'))
        return

    if nmapsn.get():
        targets_list = targets.split()
        for t in targets_list:
            if '/' not in t:
                root.after(0, lambda t=t: messagebox.showerror("Error", f"--nmap-host-discovery requires CIDR notation, but {t} is not a CIDR (e.g., /24)"))
                root.after(0, lambda: run_button.config(state='normal', text='Run Scan'))
                return
    
    # Build command
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
    if nmapsn.get():
        cmd.append("--nmap-host-discovery") 

    # Display command in output
    append_output_safe("="*80 + "\n", "header")
    append_output_safe("COMMAND EXECUTION\n", "header")
    append_output_safe("="*80 + "\n", "header")
    append_output_safe(f"Command: {' '.join(cmd)}\n\n", "command")
    
    try:
        # Run subprocess with real-time output capture
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Read output from subprocess
        def read_stream(stream, tag=None):
            try:
                for line in iter(stream.readline, ''):
                    if line:
                        append_output_safe(line, tag)
            finally:
                stream.close()
        
        # Create threads for stdout and stderr
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, None), daemon=True)
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, 'error'), daemon=True)
        
        stdout_thread.start()
        stderr_thread.start()
        
        # Wait for process to complete
        return_code = process.wait()
        
        # Wait for threads to finish reading
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        
        if return_code == 0:
            append_output_safe("\n" + "="*80 + "\n", "success")
            append_output_safe("SCAN COMPLETED SUCCESSFULLY\n", "success")
            append_output_safe("="*80 + "\n\n", "success")
            
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
            
            append_output_safe("Running CVE Collector...\n", "info")
            
            # Run CVE collector with custom output redirection
            class GUIOutputStream:
                def __init__(self, tag=None):
                    self.tag = tag
                
                def write(self, text):
                    if text and text.strip():
                        append_output_safe(text, self.tag)
                
                def flush(self):
                    pass
            
            # Redirect stdout and stderr for CVE collector
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            
            try:
                sys.stdout = GUIOutputStream()
                sys.stderr = GUIOutputStream('error')
                runcvecollector(output_dir, cve_output, scan_options)
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
            
            elapsed = time.time() - start_time
            append_output_safe(f"\n[+] All tasks completed in {elapsed:.2f} seconds.\n", "success")
            root.after(0, lambda: messagebox.showinfo("Done", f"All tasks completed in {elapsed:.2f} seconds."))
            
            # Update history (using root.after for thread-safety)
            def update_gui_history():
                update_history(recent_targets, targets)
                update_history(recent_output_dirs, output_dir_name)
                target_entry['values'] = recent_targets
                output_dir_entry['values'] = recent_output_dirs
                save_history(recent_targets, recent_output_dirs)
            
            root.after(0, update_gui_history)
        else:
            append_output_safe("\n" + "="*80 + "\n", "error")
            append_output_safe(f"ERROR: Script failed with return code {return_code}\n", "error")
            append_output_safe("="*80 + "\n", "error")
            root.after(0, lambda: messagebox.showerror("Error", f"Script failed with return code {return_code}"))
    
    except Exception as e:
        append_output_safe(f"\nException occurred: {str(e)}\n", "error")
        import traceback
        append_output_safe(traceback.format_exc(), "error")
        root.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
    
    finally:
        # Re-enable run button
        root.after(0, lambda: run_button.config(state='normal', text='Run Scan'))


# Main window setup
root = tk.Tk()
root.title("NethounD GUI")
root.geometry("1100x800")

# Set the icon
try:
    icon_path = "nethoundreport/static/logomin.png"
    if os.path.exists(icon_path):
        icon = ImageTk.PhotoImage(Image.open(icon_path))
        root.iconphoto(True, icon)
except Exception as e:
    print(f"Could not load icon: {e}")

root.minsize(800, 600)
root.configure(bg='#f0f0f0')

# Create main container - VERTICAL layout
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

main_container = tk.Frame(root, bg='#f0f0f0')
main_container.pack(fill="both", expand=True, padx=10, pady=10)

# Configure grid weights
main_container.grid_rowconfigure(0, weight=8)  # Controls section - 40% of space
main_container.grid_rowconfigure(1, weight=2)  # Output section - 60% of space
main_container.grid_columnconfigure(0, weight=1)

# TOP SECTION - Controls
controls_frame = tk.Frame(main_container, bg='#f0f0f0')
controls_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))  # Added 'ns' to make it stretch vertically

# Canvas and scrollbar for controls
canvas = tk.Canvas(controls_frame, bg='#f0f0f0', height=900)  # Increased height
scrollbar = ttk.Scrollbar(controls_frame, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas, bg="#ffffff", bd=2, relief=tk.GROOVE)

# Make controls frame expandable
controls_frame.grid_rowconfigure(0, weight=1)
controls_frame.grid_columnconfigure(0, weight=1)

scrollable_frame.grid_columnconfigure(1, weight=1)
scrollable_frame.grid_columnconfigure(2, weight=1)

canvas.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

def configure_scroll_region(event):
    canvas.configure(scrollregion=canvas.bbox("all"))

def configure_frame_width(event):
    canvas.itemconfig(canvas_frame, width=event.width-20)

scrollable_frame.bind("<Configure>", configure_scroll_region)
canvas.bind("<Configure>", configure_frame_width)

def on_mousewheel(event):
    if event.num == 5 or event.delta < 0:
        canvas.yview_scroll(1, "units")
    elif event.num == 4 or event.delta > 0:
        canvas.yview_scroll(-1, "units")

canvas.bind_all("<MouseWheel>", on_mousewheel)
canvas.bind_all("<Button-4>", on_mousewheel)
canvas.bind_all("<Button-5>", on_mousewheel)

frame = scrollable_frame
padding = {'padx': 10, 'pady': 5}

# Logo image
try:
    logo_path = "nethoundreport/static/logo.png"
    if os.path.exists(logo_path):
        logo_img = Image.open(logo_path)
        # Scale down the logo (adjust these dimensions if needed)
        logo_img = logo_img.resize((262, 107), Image.Resampling.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_img)
        logo_label = tk.Label(frame, image=logo_photo, bg="#ffffff")
        logo_label.image = logo_photo  # Keep a reference to avoid garbage collection
        logo_label.grid(row=0, column=0, columnspan=3, pady=15)
except Exception as e:
    print(f"Could not load logo for title: {e}")

# Create targets frame
targets_frame = tk.LabelFrame(frame, text="Target Settings", bg="#ffffff", padx=10, pady=5)
targets_frame.grid(row=1, column=0, columnspan=3, sticky="ew", **padding)

# Target input
tk.Label(targets_frame, text="Targets (space-separated):", bg="#ffffff").grid(row=0, column=0, sticky="w", **padding)
target_entry = ttk.Combobox(targets_frame, width=50, values=recent_targets)
cidr = get_ip_and_cidr.get_local_cidr()
if cidr:
    placeholder = cidr
else:
    placeholder = "192.168.1.0/24"
    
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

# IP address display
ip_frame = tk.Frame(targets_frame, bg="#f0f0f0", relief=tk.GROOVE, bd=2)
ip_frame.grid(row=1, column=0, columnspan=3, sticky="ew", **padding)

local_ip = get_ip_and_cidr.get_local_ip()
ip_text = f"Your IP address: {local_ip if local_ip else 'not connected'}"
ip_label = tk.Label(ip_frame, 
                   text=ip_text, 
                   bg="#f0f0f0", 
                   font=('Helvetica', 10, 'bold'),
                   fg='#2d5986',
                   pady=5,
                   padx=10)
ip_label.pack(fill='x')

# Host discovery option
nmapsn = tk.BooleanVar(value=True)
tk.Checkbutton(targets_frame, text="Use nmap host discovery (-sn)", variable=nmapsn, bg="#ffffff").grid(row=2, column=0, columnspan=3, sticky="w", **padding)

tk.Label(targets_frame, text="Output Directory:", bg="#ffffff").grid(row=3, column=0, sticky="w", **padding)
output_dir_entry = ttk.Combobox(targets_frame, width=50, values=recent_output_dirs)
output_dir_entry.grid(row=3, column=1, columnspan=2, sticky="ew", **padding)

ttk.Separator(frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky="ew", pady=10)

# Scan Options section
options_frame = tk.LabelFrame(frame, text="Scan Options", bg="#ffffff", padx=10, pady=5)
options_frame.grid(row=4, column=0, columnspan=3, sticky="ew", **padding)

# Create variables for checkboxes
sV_var = tk.BooleanVar(value=True)
sS_var = tk.BooleanVar()
sT_var = tk.BooleanVar()
sU_var = tk.BooleanVar()
A_var = tk.BooleanVar()
O_var = tk.BooleanVar()
Pn_var = tk.BooleanVar()
T4_var = tk.BooleanVar()

tk.Checkbutton(options_frame, text="-sV (Version detection)", variable=sV_var, bg="#ffffff").grid(row=0, column=0, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-sS (SYN scan)", variable=sS_var, bg="#ffffff").grid(row=1, column=0, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-sT (TCP connect scan)", variable=sT_var, bg="#ffffff").grid(row=2, column=0, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-sU (UDP scan)", variable=sU_var, bg="#ffffff").grid(row=3, column=0, sticky="w", padx=5)

tk.Checkbutton(options_frame, text="-A (Aggressive scan)", variable=A_var, bg="#ffffff").grid(row=0, column=1, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-O (OS detection)", variable=O_var, bg="#ffffff").grid(row=1, column=1, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-Pn (No ping)", variable=Pn_var, bg="#ffffff").grid(row=2, column=1, sticky="w", padx=5)
tk.Checkbutton(options_frame, text="-T4 (Aggressive timing)", variable=T4_var, bg="#ffffff").grid(row=3, column=1, sticky="w", padx=5)

# Ports Settings
additional_frame = tk.LabelFrame(frame, text="Ports Settings", bg="#ffffff", padx=10, pady=5)
additional_frame.grid(row=5, column=0, columnspan=3, sticky="ew", **padding)

top_var = tk.BooleanVar()
tk.Checkbutton(additional_frame, text="Use Top Ports", variable=top_var, bg="#ffffff").grid(row=0, column=0, sticky="w", **padding)

tk.Label(additional_frame, text="Custom Ports:", bg="#ffffff").grid(row=1, column=0, sticky="w", **padding)
ports_entry = tk.Entry(additional_frame, width=40)
ports_entry.grid(row=1, column=1, columnspan=2, sticky="ew", **padding)

# CVE output name (hidden)
cve_output_name_entry = tk.Entry(frame, width=50)
cve_output_name_entry.insert(0, "")

# Run button
run_button = tk.Button(frame, text="Run Scan", command=run_script_thread, 
                      bg="#4CAF50", fg="white", 
                      font=('Helvetica', 12, 'bold'),
                      padx=20, pady=10)
run_button.grid(row=7, column=0, columnspan=3, pady=20)

# BOTTOM SECTION - Output Display
output_container = tk.Frame(main_container, bg='#f0f0f0')
output_container.grid(row=1, column=0, sticky="nsew")

# Output frame
output_frame = tk.LabelFrame(output_container, text="Command Output", bg="#ffffff", padx=5, pady=5)
output_frame.pack(fill="both", expand=True)

# Output text widget with scrollbar
output_scrollbar = ttk.Scrollbar(output_frame)
output_scrollbar.pack(side="right", fill="y")

output_text = tk.Text(output_frame, 
                     wrap=tk.WORD, 
                     yscrollcommand=output_scrollbar.set,
                     font=('Courier', 9),
                     bg='#1e1e1e',
                     fg='#ffffff',
                     insertbackground='white',
                     state='disabled')
output_text.pack(side="left", fill="both", expand=True)
output_scrollbar.config(command=output_text.yview)

# Configure text tags for colored output
output_text.tag_config("header", foreground="#00d4ff", font=('Courier', 9, 'bold'))
output_text.tag_config("command", foreground="#ffeb3b", font=('Courier', 9))
output_text.tag_config("success", foreground="#4caf50", font=('Courier', 9, 'bold'))
output_text.tag_config("error", foreground="#f44336", font=('Courier', 9, 'bold'))
output_text.tag_config("info", foreground="#2196f3", font=('Courier', 9))

# Buttons frame for output control
button_frame = tk.Frame(output_frame, bg="#ffffff")
button_frame.pack(fill="x", pady=5)

clear_button = tk.Button(button_frame, text="Clear Output", command=clear_output,
                        bg="#ff9800", fg="white", font=('Helvetica', 9, 'bold'))
clear_button.pack(side="left", padx=5)

# Initial welcome message
append_output("="*80 + "\n", "header")
append_output("NethounD - Command Output Window\n", "header")
append_output("="*80 + "\n", "header")
append_output("Ready to scan. Configure your settings and click 'Run Scan'.\n\n", "info")

# Start the output queue processor
root.after(100, process_output_queue)

root.mainloop()