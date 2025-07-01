import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk  # type: ignore # Pillow library
import subprocess
import sys
from ingestor.cvecollector import *


def run_script():
    targets = target_entry.get().strip()
    output_dir = output_dir_entry.get().strip()
    cve_output_name= cve_output_name_entry.get().strip()
    if  cve_output_name=="":
        cve_output_name="output.json"
    if not cve_output_name.endswith('.json'):
        cve_output_name+='.json'
    cve_output = output_dir +"/"+"CVE_"+cve_output_name
    print(cve_output)
    # Collect selected options into a single quoted string
    selected_options = []
    if sV_var.get():
        selected_options.append("-sV")
    if A_var.get():
        selected_options.append("-A")
    if O_var.get():
        selected_options.append("-O")
    print(selected_options)
    # options_str = " ".join(f'"{selected_options}"')
    options_str = " ".join(f"'{opt}'" for opt in selected_options)
    # options_str =str(options_str2)
    print(options_str)
    concurrency = concurrency_entry.get()
    timeout = timeout_entry.get()
    ports = ports_entry.get().strip()
    use_top = top_var.get()

    if ports and use_top:
        messagebox.showerror("Error", "You cannot use both --top and --ports at the same time.")
        return

    # Build command
    cmd = [sys.executable, "ingestor/rustIngestor.py"]
    if targets:
        cmd += targets.split()
    if output_dir:
        cmd += ["-o", output_dir]
    if options_str:
        cmd += ["--options", options_str]
    if concurrency:
        cmd += ["--concurrency", concurrency]
    if timeout:
        cmd += ["--timeout", timeout]
    if use_top:
        cmd.append("--top")
    if ports:
        cmd += ["-p", ports]


    # Debug: print the command
    # print("Running command:", " ".join(cmd))
    print (cmd)
    result = subprocess.run(cmd)

    if result.returncode == 0:
        runcvecollector(output_dir,cve_output)
    else:
        messagebox.showerror("Error", f"Script failed with return code {result.returncode}")

# GUI layout

# Initialize window
root = tk.Tk()
root.title("RustScan Ingestor GUI")
root.geometry("700x500")

# Load and place background image
bg_image = Image.open("nmapreport/static/img/bg.png")  # Replace with your file
bg_photo = ImageTk.PhotoImage(bg_image)
background_label = tk.Label(root, image=bg_photo)
background_label.place(relwidth=1, relheight=1)

# Frame to hold widgets so they stay above background
frame = tk.Frame(root, bg="white", bd=2)
frame.place(relx=0.1, rely=0.05, relwidth=0.8, relheight=0.9)

# GUI Widgets
tk.Label(frame, text="Targets (space-separated):").grid(row=0, column=0, sticky="w")
target_entry = tk.Entry(frame, width=50)
target_entry.grid(row=0, column=1)

tk.Label(frame, text="Output Directory:").grid(row=1, column=0, sticky="w")
output_dir_entry = tk.Entry(frame, width=50)
output_dir_entry.grid(row=1, column=1)



tk.Label(frame, text="Options:").grid(row=2, column=0, sticky="w")
sV_var = tk.BooleanVar(value=True)
A_var = tk.BooleanVar()
O_var = tk.BooleanVar()
tk.Checkbutton(frame, text="-sV", variable=sV_var).grid(row=2, column=1, sticky="w")
tk.Checkbutton(frame, text="-A", variable=A_var).grid(row=3, column=1, sticky="w")
tk.Checkbutton(frame, text="-O", variable=O_var).grid(row=4, column=1, sticky="w")

tk.Label(frame, text="Concurrency:").grid(row=5, column=0, sticky="w")
concurrency_entry = tk.Entry(frame)
concurrency_entry.insert(0, "4")
concurrency_entry.grid(row=5, column=1)

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

tk.Button(frame, text="Run", command=run_script).grid(row=10, column=1, pady=10)

root.mainloop()