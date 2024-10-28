import os
import sys
import threading
import subprocess
import socket
import time
import tkinter as tk
import csv
from datetime import datetime

# Dependency list
REQUIRED_PACKAGES = ['flask', 'pyautogui', 'pyOpenSSL', 'qrcode', 'Pillow']

# Function to check and install dependencies
def check_and_install_dependencies():
    import importlib
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
        except ImportError:
            print(f"Package '{package}' not found. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

# Call the function to ensure dependencies are installed
check_and_install_dependencies()

# Now import the packages after ensuring they are installed
from flask import Flask, render_template, request, jsonify

import pyautogui
import ssl
from OpenSSL import crypto
import qrcode
from PIL import Image, ImageTk

# Shared variables and locks
last_scanned_code = ''
last_scanned_format = ''
scan_lock = threading.Lock()

# Variables to track scans and settings
output_mode = None  # Will be initialized in run_gui()
cooldown_time = None  # Will be initialized in run_gui()
default_cooldown = 2  # Default cooldown time
total_scans = 0  # Counter for total scans
total_scans_lock = threading.Lock()

# Variables to track connected users
connected_users = {}
connected_users_lock = threading.Lock()

# Global root for Tkinter
root = None

# Function to generate SSL certificate
def generate_ssl_cert():
    from pathlib import Path

    cert_file = Path('cert.pem')
    key_file = Path('key.pem')

    if not cert_file.exists() or not key_file.exists():
        print("SSL certificates not found. Generating new self-signed certificates...")
        try:
            from OpenSSL import crypto
        except ImportError:
            print("Package 'pyOpenSSL' not found. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyOpenSSL'])
            from OpenSSL import crypto

        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)

        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Unit"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        print("SSL certificates generated.")
    else:
        print("SSL certificates found.")

# Function to read SSL certificate info
def get_cert_info():
    cert_file = 'cert.pem'
    try:
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        valid_from = cert.get_notBefore().decode('ascii')
        valid_to = cert.get_notAfter().decode('ascii')
        return {
            'subject': dict((name.decode(), value.decode()) for name, value in subject.get_components()),
            'issuer': dict((name.decode(), value.decode()) for name, value in issuer.get_components()),
            'valid_from': valid_from,
            'valid_to': valid_to
        }
    except Exception as e:
        print(f"Error reading certificate: {e}")
        return None

# Ensure pyautogui is properly set up
def setup_pyautogui():
    # On macOS, pyautogui might need accessibility permissions
    if sys.platform == 'darwin':
        print("Ensure that the app has accessibility permissions in System Preferences.")

# Function to get the local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Main function to run the app
def main():
    global root, output_mode, cooldown_time

    # Generate SSL certificates if not present
    generate_ssl_cert()

    # Set up pyautogui
    setup_pyautogui()

    # Start the Flask app in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    # Start the GUI
    run_gui()

def run_flask_app():
    global cooldown_time, total_scans
    app = Flask(__name__, template_folder='web_views')  # Updated template_folder

    @app.route('/')
    def index():
        # Record user's IP address as connected
        user_ip = request.remote_addr
        with connected_users_lock:
            connected_users[user_ip] = time.time()
        # Pass the cooldown time to the template
        try:
            cooldown = int(cooldown_time.get())
        except (tk.TclError, ValueError):
            cooldown = default_cooldown  # Use default if invalid
        return render_template('index.html', cooldown_time=cooldown)

    @app.route('/keepalive', methods=['POST'])
    def keepalive():
        user_ip = request.remote_addr
        with connected_users_lock:
            connected_users[user_ip] = time.time()
        return 'OK', 200

    @app.route('/disconnect', methods=['POST'])
    def disconnect():
        # Remove user's IP address from connected users
        user_ip = request.remote_addr
        with connected_users_lock:
            connected_users.pop(user_ip, None)
        return 'OK', 200

    @app.route('/scan', methods=['POST'])
    def scan():
        data = request.json
        barcode_data = data.get('barcode')
        barcode_format = data.get('format', 'Unknown')
        if barcode_data:
            # Update last scanned code and format
            with scan_lock:
                global last_scanned_code, last_scanned_format, total_scans
                last_scanned_code = barcode_data
                last_scanned_format = barcode_format

                # Increment total scans
                with total_scans_lock:
                    total_scans += 1

            # Update the GUI
            def update_gui():
                last_code_label_var.set(f'Last Scanned Code: {barcode_data}')
                last_format_label_var.set(f'Last Scanned Format: {barcode_format}')
                total_scans_label_var.set(f'Total Scans: {total_scans}')
            root.after(0, update_gui)

            # Output based on selected mode
            if output_mode.get() == 'keyboard':
                threading.Thread(target=type_barcode, args=(barcode_data,)).start()
            elif output_mode.get() == 'csv':
                threading.Thread(target=write_to_csv, args=(barcode_data, barcode_format)).start()
        return 'OK', 200

    @app.route('/settings')
    def get_settings():
        try:
            cooldown = int(cooldown_time.get())
        except (tk.TclError, ValueError):
            cooldown = default_cooldown  # Use default if invalid
        return jsonify({
            'cooldown_time': cooldown
        })

    def type_barcode(barcode_data):
        pyautogui.typewrite(barcode_data)
        pyautogui.press('enter')

    def write_to_csv(barcode_data, barcode_format):
        file_exists = os.path.isfile('scanned_codes.csv')
        with open('scanned_codes.csv', 'a', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write headers if file doesn't exist
            if not file_exists:
                csv_writer.writerow(['Timestamp', 'Barcode Data', 'Format'])
            csv_writer.writerow([datetime.now().isoformat(), barcode_data, barcode_format])

    # Start a background thread to clean up inactive users
    def cleanup_users():
        while True:
            current_time = time.time()
            with connected_users_lock:
                inactive_users = [ip for ip, last_time in connected_users.items() if current_time - last_time > 60]
                for ip in inactive_users:
                    del connected_users[ip]
            time.sleep(30)

    threading.Thread(target=cleanup_users, daemon=True).start()

    # Run the app
    context = ('cert.pem', 'key.pem')  # Paths to your certificate and key files
    app.run(host='0.0.0.0', port=5000, ssl_context=context, threaded=True)

def run_gui():
    global root, output_mode, cooldown_time, last_code_label_var, last_format_label_var, total_scans_label_var

    # Create the main window
    root = tk.Tk()
    root.title("Barcode Scanner Host App")

    # Add a prominent title
    title_label = tk.Label(root, text="Barcode Scanner Host Application", font=("Helvetica", 16, "bold"))
    title_label.pack(pady=10)

    # Labels to display information
    ip_address = get_local_ip()
    server_url = f"https://{ip_address}:5000"
    address_label = tk.Label(root, text=f"Server Address: {server_url}", font=("Helvetica", 12))
    address_label.pack(pady=5)

    # Generate QR code of the server address
    qr_image = generate_qr_code(server_url)
    qr_label = tk.Label(root, image=qr_image)
    qr_label.image = qr_image  # Keep a reference
    qr_label.pack(pady=5)

    # Status indicator
    status_frame = tk.Frame(root)
    status_frame.pack(pady=5)
    status_label = tk.Label(status_frame, text="Server Status:", font=("Helvetica", 12))
    status_label.pack(side='left')
    status_canvas = tk.Canvas(status_frame, width=20, height=20)
    status_canvas.pack(side='left')
    status_indicator = status_canvas.create_oval(5, 5, 15, 15, fill='green')

    users_label_var = tk.StringVar()
    users_label = tk.Label(root, textvariable=users_label_var, font=("Helvetica", 12))
    users_label.pack(pady=5)

    # Total scans label
    total_scans_label_var = tk.StringVar(value='Total Scans: 0')
    total_scans_label = tk.Label(root, textvariable=total_scans_label_var, font=("Helvetica", 12))
    total_scans_label.pack(pady=5)

    # Last scanned code and format
    last_code_label_var = tk.StringVar(value='Last Scanned Code: None')
    last_format_label_var = tk.StringVar(value='Last Scanned Format: None')
    last_code_label = tk.Label(root, textvariable=last_code_label_var, font=("Helvetica", 12))
    last_format_label = tk.Label(root, textvariable=last_format_label_var, font=("Helvetica", 12))
    last_code_label.pack(pady=5)
    last_format_label.pack(pady=5)

    # Certificate Information
    cert_info = get_cert_info()
    if cert_info:
        cert_label = tk.Label(root, text="SSL Certificate Information:", font=("Helvetica", 12, "bold"))
        cert_label.pack(pady=5)
        cert_details = f"""
Subject CN: {cert_info['subject'].get('CN', 'N/A')}
Issuer CN: {cert_info['issuer'].get('CN', 'N/A')}
Valid From: {cert_info['valid_from']}
Valid To: {cert_info['valid_to']}
"""
        cert_info_label = tk.Label(root, text=cert_details.strip(), justify='left', font=("Helvetica", 10))
        cert_info_label.pack(pady=5)
    else:
        cert_info_label = tk.Label(root, text="Unable to retrieve SSL certificate information.")
        cert_info_label.pack(pady=5)

    # Output mode selection
    output_mode_label = tk.Label(root, text="Output Mode:", font=("Helvetica", 12, "bold"))
    output_mode_label.pack(pady=5)
    output_mode_frame = tk.Frame(root)
    output_mode_frame.pack()

    output_mode = tk.StringVar(value='keyboard')
    output_mode_keyboard = tk.Radiobutton(output_mode_frame, text='Keyboard', variable=output_mode, value='keyboard', font=("Helvetica", 12))
    output_mode_csv = tk.Radiobutton(output_mode_frame, text='CSV File', variable=output_mode, value='csv', font=("Helvetica", 12))
    output_mode_keyboard.pack(side='left', padx=5)
    output_mode_csv.pack(side='left', padx=5)

    # Cooldown time setting with validation
    cooldown_label = tk.Label(root, text="Cooldown Time (seconds):", font=("Helvetica", 12, "bold"))
    cooldown_label.pack(pady=5)
    cooldown_time = tk.StringVar(value=str(default_cooldown))

    # Add validation to ensure only integers are entered
    def validate_cooldown(value_if_allowed):
        if value_if_allowed == '':
            return True  # Allow empty string (user may be in the process of typing)
        try:
            int(value_if_allowed)
            return True
        except ValueError:
            return False

    vcmd = (root.register(validate_cooldown), '%P')
    cooldown_entry = tk.Entry(root, textvariable=cooldown_time, font=("Helvetica", 12), width=5, validate='key', validatecommand=vcmd)
    cooldown_entry.pack(pady=5)

    # Instructions
    instructions_label = tk.Label(root, text="", justify='left', font=("Helvetica", 10))
    instructions_label.pack(pady=10)

    # "Made by Clément GHANEME" button
    made_by_button = tk.Button(root, text="Made by Clément GHANEME", font=("Helvetica", 10), command=open_website)
    made_by_button.pack(pady=5)

    # Disclaimer
    disclaimer_label = tk.Label(root, text='The software is provided "as is" and I am not responsible for its usage or any issues arising from using it.', font=("Helvetica", 8), wraplength=400, justify='center')
    disclaimer_label.pack(pady=5)

    update_users_label(users_label_var, root)
    update_instructions(instructions_label)

    # Close button
    close_button = tk.Button(root, text="Close", command=lambda: on_close(root), font=("Helvetica", 12))
    close_button.pack(pady=10)

    root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
    root.mainloop()

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img = img.resize((150, 150))  # Resize to fit in the GUI
    return ImageTk.PhotoImage(img)

def open_website():
    import webbrowser
    webbrowser.open('https://clement.business/')

def update_users_label(label_var, root):
    # Update the number of connected users every second
    def update_label():
        current_time = time.time()
        with connected_users_lock:
            num_users = sum(1 for last_time in connected_users.values() if current_time - last_time <= 60)
        label_var.set(f"Connected Users: {num_users}")
        # Schedule the function to run again after 1000ms
        root.after(1000, update_label)
    update_label()

def update_instructions(instructions_label):
    # Update the instructions when settings change
    def update_text(*args):
        # Safely get the cooldown time
        try:
            cooldown = int(cooldown_time.get())
        except (tk.TclError, ValueError):
            cooldown = default_cooldown  # Use default if invalid

        instructions = f"""
Instructions:
1. On your device, navigate to the server address displayed above.
2. You can scan the QR code to access the page easily.
3. Allow camera access when prompted.
4. Align the barcode within the camera view to scan.
5. The scanned data will be {'typed as keyboard input' if output_mode.get() == 'keyboard' else 'saved to a CSV file'}.
6. Cooldown Time between scans is set to {cooldown} seconds.
7. Supported code formats: QR Code, Data Matrix, Aztec, PDF417, Code 128, Code 39, Code 93, EAN-8, EAN-13, UPC-A, UPC-E, Codabar, ITF (Interleaved 2 of 5).
"""
        instructions_label.config(text=instructions.strip())

    output_mode.trace('w', update_text)
    cooldown_time.trace('w', update_text)

    # Initial call to set instructions
    update_text()

def on_close(root):
    # Function to handle closing the app
    print("Shutting down...")
    # Do any cleanup here if necessary
    os._exit(0)  # Forcefully exit the entire program

if __name__ == '__main__':
    main()
