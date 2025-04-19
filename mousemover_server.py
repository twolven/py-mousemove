###############################################################################
# MouseMoveR_Server.py - Server Python v4.2 (Corrected Syntax, Custom Config)
###############################################################################

import socket
import time
import threading
import sys
import signal
import psutil # For process killing
import keyboard # For hotkey polling
import ctypes # For message box and IPC
import win32pipe, win32file, pywintypes # For IPC
import os
from typing import Optional

# --- Global configuration (Defaults) ---
DEVICE_ID = "GWire.17"
SERVER_PORT = 8080
HEARTBEAT_TIMEOUT = 17 # Timeout since last command
WARNING_INTERVAL = 60
PROCESS_TO_KILL = ""
HOTKEY = ""
POLL_INTERVAL = 5 # Interval for status_checker loop (IPC checks)

# --- Global State ---
running = True
socket_lock = threading.Lock()
is_focused = False
is_client_connected = False # Managed by status checker / handler
last_command_time = time.monotonic()
last_disconnect_warning_time = 0

# --- Helper: Logger ---
def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] [Server] {message}", flush=True)

# --- *** CUSTOM CONFIG LOADER *** ---
def load_config_custom(filename="config.txt"):
    """Loads configuration from the original key=value format file."""
    global DEVICE_ID, SERVER_PORT, HEARTBEAT_TIMEOUT, WARNING_INTERVAL, \
           PROCESS_TO_KILL, HOTKEY, POLL_INTERVAL

    log(f"Attempting to load config from: {filename}")
    loaded_values = 0
    try:
        if getattr(sys, 'frozen', False): base_dir = os.path.dirname(sys.executable)
        else: base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, filename)

        if not os.path.exists(config_path):
             log(f"ERROR: Config file not found at '{config_path}'. Using defaults.")
             print_effective_config()
             return True

        with open(config_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'): continue
                if '=' not in line: continue

                key, sep, value = line.partition('=')
                key = key.strip(); value = value.strip()
                try:
                    if key == "DEVICE_ID": DEVICE_ID = value; loaded_values += 1
                    elif key == "SERVER_PORT": SERVER_PORT = int(value); loaded_values += 1
                    elif key == "HEARTBEAT_TIMEOUT": HEARTBEAT_TIMEOUT = int(value); loaded_values += 1
                    elif key == "WARNING_INTERVAL": WARNING_INTERVAL = int(value); loaded_values += 1
                    elif key == "PROCESS_TO_KILL": PROCESS_TO_KILL = value; loaded_values += 1
                    elif key == "HOTKEY": HOTKEY = value; loaded_values += 1
                    elif key == "POLL_INTERVAL": POLL_INTERVAL = int(value); loaded_values += 1
                    elif key in ["SERVER_IP", "VHUSB_CHECK_INTERVAL", "WINDOW_TITLE", "CONNECT_RETRY_DELAY", "HEARTBEAT_INTERVAL"]: pass
                    else: log(f"Warning: Unknown config key '{key}' on line {line_num}")
                except ValueError: log(f"Warning: Invalid integer value for key '{key}' on line {line_num}: '{value}'")
                except Exception as e: log(f"Warning: Error processing line {line_num}: {e}")

        if loaded_values > 0: log("Configuration loaded successfully.")
        else: log("Warning: No valid configuration values loaded. Using defaults.")
        print_effective_config()
        return True

    except Exception as e:
        log(f"ERROR loading config file '{config_path}': {e}. Using defaults.")
        print_effective_config()
        return True

def print_effective_config():
     log("Effective configuration:")
     log(f"  DEVICE_ID        : {DEVICE_ID}")
     log(f"  SERVER_PORT      : {SERVER_PORT}")
     log(f"  HEARTBEAT_TIMEOUT: {HEARTBEAT_TIMEOUT}s (Since last command)")
     log(f"  WARNING_INTERVAL : {WARNING_INTERVAL}s")
     log(f"  POLL_INTERVAL    : {POLL_INTERVAL}s (Status Check Interval)")
     log(f"  PROCESS_TO_KILL  : '{PROCESS_TO_KILL or '[Not Set]'}'")
     log(f"  HOTKEY           : '{HOTKEY or '[Not Set]'}'")

# --- SendToIPC ---
def send_to_ipc(command: str) -> tuple[bool, str, Optional[int]]:
    # ... (Function body unchanged from v4.1) ...
    pipe_name = r'\\.\pipe\vhclient'; full_command = command
    if command in ["USE", "STOP USING", "DEVICE INFO"]: full_command = f"{command},{DEVICE_ID}"
    try:
        handle = win32file.CreateFile(pipe_name, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None)
        win32file.WriteFile(handle, full_command.encode('utf-8'))
        hr, resp_bytes = win32file.ReadFile(handle, 4096); response = resp_bytes.decode('utf-8', errors='ignore').strip()
        win32file.CloseHandle(handle); return True, response, None
    except pywintypes.error as e:
        if e.winerror != 2: log(f"[IPC] pywintypes error {e.winerror} for '{full_command}': {e.strerror}")
        return False, "", e.winerror
    except Exception as e: log(f"[IPC] Unexpected error for '{full_command}': {e}"); return False, "", -1

# --- Warning Message Display ---
def show_warning(message: str):
    # ... (Function body unchanged from v4.1) ...
    log(f"Showing Warning: {message}")
    threading.Thread(target=ctypes.windll.user32.MessageBoxW, args=(0, message, "MouseMoveR Warning", 0x30 | 0x1000), daemon=True).start()

# --- Process Killing Function ---
def find_and_kill_process():
    # ... (Function body unchanged from v4.1) ...
    if not PROCESS_TO_KILL: log("[Kill] Hotkey ignored: Not configured."); return
    log(f"[Kill] Hotkey! Searching for '{PROCESS_TO_KILL}'..."); p_lower = PROCESS_TO_KILL.lower(); found = 0; killed = 0
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pinfo = proc.info
                if pinfo.get('name') and pinfo['name'].lower() == p_lower:
                    found += 1; log(f"  [+] Found PID: {pinfo['pid']} ({pinfo['name']})"); p = psutil.Process(pinfo['pid'])
                    try: log(f"      Terminating..."); p.terminate(); p.wait(1); log(f"      Terminated."); killed += 1
                    except psutil.TimeoutExpired: log(f"      Timeout, killing..."); p.kill(); p.wait(0.5); log(f"      Killed."); killed += 1
                    except psutil.NoSuchProcess: log(f"      Gone."); killed += 1
                    except psutil.AccessDenied: log(f"      Access Denied (Admin?).")
                    except Exception as te: log(f"      Error killing PID {pinfo['pid']}: {te}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
        if not found: log(f"[Kill] Process not found.")
        else: log(f"[Kill] Done. Found:{found}, Killed:{killed}.")
    except Exception as e: log(f"[Kill] Error iterating: {e}")

# --- Hotkey Listener Thread ---
def hotkey_listener():
    # ... (Function body mostly unchanged from v4.1) ...
    if not HOTKEY: log("[Hotkey] Disabled."); return
    hotkey_norm = HOTKEY.replace('\\', 'backslash')
    log(f"[Hotkey] Starting listener for key: '{hotkey_norm}'...")
    try:
        keyboard.add_hotkey(hotkey_norm, find_and_kill_process, suppress=False, trigger_on_release=False)
        log(f"[Hotkey] Listener registered for '{hotkey_norm}'.")
        while running: time.sleep(1)
    except ImportError: log("[Hotkey] ERROR: 'keyboard' library not installed (pip install keyboard).")
    except Exception as e: log(f"[Hotkey] ERROR setup: {e} (Try Run as Admin?)")
    log("[Hotkey] Listener thread exiting.")
    try:
        keyboard.remove_all_hotkeys()
    # --- SYNTAX FIX 1 ---
    except Exception: # Catch general Exception instead of bare except
        pass # Ignore cleanup errors
    # --- END FIX 1 ---

# --- Persistent Client Connection Handling ---
def handle_client(client_socket: socket.socket, address: tuple):
    # ... (Function body unchanged from v4.1 - Handles IPC Busy, Failsafe) ...
    global is_focused, is_client_connected, last_command_time
    ip, port = address; log(f"[Handler:{port}] Connection from {ip}:{port}"); client_had_focus = False
    recv_timeout = HEARTBEAT_TIMEOUT + 5; client_socket.settimeout(recv_timeout)
    try:
        with socket_lock: is_client_connected = True; last_command_time = time.monotonic()
        while running:
            data = client_socket.recv(1024);
            if not data: log(f"[Handler:{port}] Client disconnected."); break
            command = data.decode('utf-8', errors='ignore').strip();
            if not command: continue
            log(f"[Handler:{port}] Rcvd: '{command}'")
            with socket_lock: is_client_connected = True; last_command_time = time.monotonic()
            reply = "NACK"; ipc_resp = ""; ipc_err = None; suc = False; stop_err = None

            if command == "FOCUSED":
                with socket_lock: is_focused = True; client_had_focus = True
                suc, _, ipc_err = send_to_ipc("USE")
                if suc or ipc_err == 231: reply = "ACK"
                if ipc_err == 231: log(f"[Handler:{port}] IPC busy on USE. Acked client.")
                elif not suc: log(f"[Handler:{port}] Failed 'USE' IPC (Err:{ipc_err}).")
            elif command == "NOT_FOCUSED":
                with socket_lock: is_focused = False; client_had_focus = False
                suc, ipc_resp, ipc_err = send_to_ipc("DEVICE INFO")
                if suc:
                    if "IN USE BY: NO ONE" not in ipc_resp:
                        stop_suc, _, stop_err = send_to_ipc("STOP USING")
                        if stop_suc or stop_err == 231: reply = "ACK"
                        if stop_err == 231: log(f"[Handler:{port}] IPC busy on STOP. Acked client.")
                        elif not stop_suc: log(f"[Handler:{port}] Failed 'STOP' IPC (Err:{stop_err}).")
                    else: reply = "ACK"
                elif ipc_err == 231: log(f"[Handler:{port}] IPC busy on INFO. Acked client."); reply = "ACK"
                else: log(f"[Handler:{port}] Failed 'INFO' IPC (Err:{ipc_err}).")
            elif command == "VHUSB_NOT_RUNNING": show_warning(f"Client {ip}:{port} reports VH client not running!"); reply = "ACK"
            elif command == "HEARTBEAT": reply = "ACK" # Handle heartbeat
            else: log(f"[Handler:{port}] Unknown cmd: '{command}'"); reply = "UNKNOWN"
            client_socket.sendall(reply.encode('utf-8'))
    except socket.timeout: log(f"[Handler:{port}] Client recv timed out.")
    except OSError as e: log(f"[Handler:{port}] Socket error: {e}.")
    except Exception as e: log(f"[Handler:{port}] Unexpected error: {e}.")
    finally: # Failsafe logic
        log(f"[Handler:{port}] Cleaning up connection.")
        if client_had_focus:
            log(f"[Handler:{port}] Failsafe check: Client had focus.")
            with socket_lock: current_focus = is_focused
            if current_focus:
                 log("[Failsafe] Attempting STOP USING..."); suc, _, err = send_to_ipc("STOP USING")
                 if suc: log("[Failsafe] STOP USING sent.")
                 else: log(f"[Failsafe] STOP USING failed (Err:{err}). Manual check needed?")
            else: log("[Failsafe] Focus already false.")
            with socket_lock: is_focused = False
        try: client_socket.shutdown(socket.SHUT_RDWR); client_socket.close()
        except OSError: pass


# --- Status Checker Thread ---
def status_checker():
    # ... (Function body unchanged from v4.1 - checks timeout/warnings/IPC) ...
    global is_client_connected, is_focused, last_command_time, last_disconnect_warning_time
    log("[Status] Status checker thread started."); check_interval = max(1, POLL_INTERVAL)
    log(f"[Status] Performing checks every {check_interval}s.")
    while running:
        time.sleep(check_interval);
        if not running: break
        now = time.monotonic(); disconnected = False
        with socket_lock: # Check shared state
            if is_client_connected and (now - last_command_time > HEARTBEAT_TIMEOUT):
                log(f"[Status] Client timed out ({HEARTBEAT_TIMEOUT}s). Marking disconnected.")
                is_client_connected = False; is_focused = False; disconnected = True
                last_disconnect_warning_time = 0
            show_warning_flag = not is_client_connected and (now - last_command_time > WARNING_INTERVAL) # Note: Mismatch logic here - check time since last warning
            check_ipc_flag = is_focused

        # Corrected warning logic: Check time since last warning was shown
        if not is_client_connected and (now - last_disconnect_warning_time > WARNING_INTERVAL):
            if not disconnected: # Don't show warning immediately after timeout disconnect
                 show_warning("No connection from MouseMove client.");
            last_disconnect_warning_time = now # Reset timer regardless

        if check_ipc_flag: # IPC check outside lock
            ipc_suc, ipc_resp, _ = send_to_ipc("DEVICE INFO")
            if ipc_suc:
                if "IN USE BY: NO ONE" in ipc_resp: log("[Status] Device idle while focused, re-acquiring..."); send_to_ipc("USE")
                elif "IN USE BY:" in ipc_resp and "IN USE BY: YOU" not in ipc_resp and f"IN USE BY: {DEVICE_ID}" not in ipc_resp: log("[Status] Warn: Device used by other while focused.")

    log("[Status] Status checker thread exiting.")


# --- Signal Handler ---
def signal_handler(sig, frame):
    # ... (Function body unchanged from v4.1) ...
     global running; log("Shutdown signal received!"); running = False

# --- Main Server Execution ---
if __name__ == "__main__":
    log("Starting MouseMoveR Server (v4.2 - Custom Config)...")
    if not load_config_custom(): # <<< USE CUSTOM LOADER
        pass # Continue with defaults
    signal.signal(signal.SIGINT, signal_handler); signal.signal(signal.SIGTERM, signal_handler)

    # Start background threads using global config implicitly
    if PROCESS_TO_KILL and HOTKEY: threading.Thread(target=hotkey_listener, daemon=True).start()
    else: log("[Main] Hotkey disabled.")
    threading.Thread(target=status_checker, daemon=True).start()

    # Main Server Loop (Accept Connections)
    server_sock: Optional[socket.socket] = None
    try:
        server_address = ('0.0.0.0', SERVER_PORT) # Use global
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(server_address); server_sock.listen(5)
        log(f"Server listening on {server_address[0]}:{server_address[1]}...")
        while running:
            try:
                server_sock.settimeout(1.0); client_socket, client_address = server_sock.accept(); server_sock.settimeout(None)
                threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start() # Start persistent handler
            except socket.timeout: continue # Check running flag
            # --- SYNTAX FIX 2 ---
            except OSError as e:
                if running: # Log only if not shutting down
                    log(f"Server accept error: {e}")
                break # Exit accept loop on error
            # --- END FIX 2 ---
            except Exception as e: # Catch other potential errors
                log(f"Server main loop error: {e}")
                break # Exit accept loop on other errors
    except Exception as e: log(f"FATAL: Server setup error: {e}")
    finally:
        log("Server main loop exiting."); running = False
        log("Closing listening socket...");
        if server_sock: server_sock.close()
        log("Waiting briefly for threads..."); time.sleep(0.5)
        log("Cleanup complete. Exiting.")