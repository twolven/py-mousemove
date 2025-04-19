###############################################################################
# MouseMoveR_Server.py - Server Python v3.0 (Custom Config, Simplified Persistent)
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
# HEARTBEAT_TIMEOUT = 17 # REMOVED - Rely on socket timeout/disconnect
POLL_INTERVAL = 2
WARNING_INTERVAL = 60
PROCESS_TO_KILL = ""
HOTKEY = ""

# --- Global State ---
running = True
socket_lock = threading.Lock() # Lock for accessing shared focus state below
# client_connections = {} # Not strictly needed in simplified version
is_focused = False # Focus state reported by the primary client
# is_client_connected = False # REMOVED - Handled by connection presence
# last_command_time = time.monotonic() # REMOVED
last_disconnect_warning_time = 0

# --- Helper: Logger ---
def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] [Server] {message}", flush=True)

# --- CUSTOM CONFIG LOADER ---
def load_config_custom(filename="config.txt"):
    """Loads configuration from the original format file into global variables."""
    global DEVICE_ID, SERVER_PORT, WARNING_INTERVAL, PROCESS_TO_KILL, HOTKEY # Removed HEARTBEAT_TIMEOUT

    log(f"Attempting to load config from: {filename}")
    try:
        # Determine path relative to script/exe
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
                if '=' not in line: continue # Skip malformed lines quietly

                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                try:
                    if key == "DEVICE_ID": DEVICE_ID = value
                    elif key == "SERVER_PORT": SERVER_PORT = int(value)
                    # elif key == "HEARTBEAT_TIMEOUT": HEARTBEAT_TIMEOUT = int(value) # Removed
                    elif key == "WARNING_INTERVAL": WARNING_INTERVAL = int(value)
                    elif key == "PROCESS_TO_KILL": PROCESS_TO_KILL = value
                    elif key == "HOTKEY": HOTKEY = value
                    # Ignore client-specific keys
                    elif key in ["SERVER_IP", "POLL_INTERVAL", "VHUSB_CHECK_INTERVAL", "WINDOW_TITLE"]:
                        pass
                    else: log(f"Warning: Unknown config key '{key}' on line {line_num}")
                except ValueError: log(f"Warning: Invalid integer value for key '{key}' on line {line_num}: '{value}'")
                except Exception as e: log(f"Warning: Error processing config line {line_num}: {e}")

        log("Configuration loaded successfully.")
        print_effective_config()
        return True

    except Exception as e:
        log(f"ERROR loading config file '{config_path}': {e}")
        log("Using default values.")
        print_effective_config()
        return True

def print_effective_config():
    """Prints the currently active configuration values."""
    log("Effective configuration:")
    log(f"  DEVICE_ID        : {DEVICE_ID}")
    log(f"  SERVER_PORT      : {SERVER_PORT}")
    # log(f"  HEARTBEAT_TIMEOUT: {HEARTBEAT_TIMEOUT}s (Since last command)") # Removed
    log(f"  WARNING_INTERVAL : {WARNING_INTERVAL}s")
    log(f"  PROCESS_TO_KILL  : '{PROCESS_TO_KILL or '[Not Set]'}'")
    log(f"  HOTKEY           : '{HOTKEY or '[Not Set]'}'")

# --- SendToIPC (Uses global DEVICE_ID) ---
def send_to_ipc(command: str) -> tuple[bool, str]:
    pipe_name = r'\\.\pipe\vhclient'
    full_command = command # Default for commands not needing ID
    if command in ["USE", "STOP USING", "DEVICE INFO"]:
        full_command = f"{command},{DEVICE_ID}" # Use global DEVICE_ID

    try:
        handle = win32file.CreateFile( pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None,
            win32file.OPEN_EXISTING, 0, None )
        # log(f"[IPC] Sending: {full_command}") # Debug
        win32file.WriteFile(handle, full_command.encode('utf-8'))
        hr, resp_bytes = win32file.ReadFile(handle, 4096)
        response = resp_bytes.decode('utf-8', errors='ignore').strip()
        # log(f"[IPC] Received: {response}") # Debug
        win32file.CloseHandle(handle)
        return True, response
    except pywintypes.error as e:
        if e.winerror != 2: # Only log if not "File not found"
             log(f"[IPC] pywintypes error {e.winerror}: {e.strerror}")
        return False, ""
    except Exception as e:
        log(f"[IPC] Unexpected error: {e}")
        return False, ""

# --- Warning Message Display (Threaded) ---
def show_warning(message: str):
    log(f"Showing Warning: {message}")
    threading.Thread(target=ctypes.windll.user32.MessageBoxW,
                     args=(0, message, "MouseMoveR Warning", 0x30 | 0x1000),
                     daemon=True).start()

# --- Process Killing Function ---
def find_and_kill_process():
    if not PROCESS_TO_KILL: log("[Kill] Hotkey ignored: PROCESS_TO_KILL not set."); return # Use global
    log(f"[Kill] Hotkey pressed! Searching for '{PROCESS_TO_KILL}'...")
    process_name_lower = PROCESS_TO_KILL.lower(); found = 0; killed = 0
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pinfo = proc.info
                if pinfo['name'] and pinfo['name'].lower() == process_name_lower:
                    found += 1; log(f"  [+] Found PID: {pinfo['pid']} ({pinfo['name']})")
                    try:
                        p = psutil.Process(pinfo['pid']); log(f"      Terminating...")
                        p.terminate(); p.wait(timeout=1); log(f"      Terminated."); killed += 1
                    except psutil.TimeoutExpired: log(f"      Timeout, force killing..."); p.kill(); p.wait(timeout=0.5); log(f"      Killed."); killed += 1
                    except psutil.NoSuchProcess: log(f"      Process gone."); killed += 1
                    except psutil.AccessDenied: log(f"      Access Denied (Run as Admin?).")
                    except Exception as te: log(f"      Error killing PID {pinfo['pid']}: {te}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
        if not found: log(f"[Kill] Process not found.")
        else: log(f"[Kill] Finished. Found:{found}, Killed:{killed}.")
    except Exception as e: log(f"[Kill] Error iterating processes: {e}")

# --- Hotkey Listener Thread (Polling Method) ---
def hotkey_listener():
    if not HOTKEY: log("[Hotkey] Disabled."); return # Use global
    hotkey_str_norm = HOTKEY.replace('\\', 'backslash') # Use global, normalize
    log(f"[Hotkey] Starting listener for key: '{hotkey_str_norm}'...")
    try:
        keyboard.add_hotkey(hotkey_str_norm, find_and_kill_process, suppress=False, trigger_on_release=False)
        log(f"[Hotkey] Listener registered for '{hotkey_str_norm}'.")
        while running: time.sleep(1) # Keep thread alive
    except ImportError: log("[Hotkey] ERROR: 'keyboard' library not installed.")
    except Exception as e: log(f"[Hotkey] ERROR setup: {e} (Try Run as Admin?)")
    log("[Hotkey] Listener thread exiting.")
    try: keyboard.remove_all_hotkeys()
    except: pass

# --- Persistent Client Connection Handling ---
def handle_client(client_socket: socket.socket, address: tuple):
    global is_focused # Modifies global focus state
    ip, port = address
    log(f"[Handler:{port}] Connection accepted from {ip}:{port}")
    client_socket.settimeout(60.0) # Generous timeout for recv, relies on client sending

    try:
        while running: # Keep handling commands until disconnect or shutdown
            data = client_socket.recv(1024)
            if not data: log(f"[Handler:{port}] Client disconnected."); break
            command = data.decode('utf-8', errors='ignore').strip()
            if not command: continue # Ignore empty commands
            log(f"[Handler:{port}] Rcvd: '{command}'")

            # Update shared state - ANY command resets the "timeout" conceptually
            # last_command_time doesn't strictly need locking if only written here
            # is_client_connected also doesn't strictly need locking if only written here

            reply_str = "NACK" # Default reply

            # Process commands
            if command == "FOCUSED":
                with socket_lock: is_focused = True # Lock only needed for shared state write
                success, _ = send_to_ipc("USE") # Use global DEVICE_ID implicitly
                if success: reply_str = "ACK"
                else: log(f"[Handler:{port}] Failed 'USE' IPC.")
            elif command == "NOT_FOCUSED":
                with socket_lock: is_focused = False # Lock for shared state write
                success, ipc_resp = send_to_ipc("DEVICE INFO")
                if success:
                    if "IN USE BY: NO ONE" not in ipc_resp:
                        stop_success, _ = send_to_ipc("STOP USING")
                        if stop_success: reply_str = "ACK"
                        else: log(f"[Handler:{port}] Failed 'STOP USING' IPC.")
                    else: reply_str = "ACK" # Is "NO ONE"
                else: log(f"[Handler:{port}] Failed 'DEVICE INFO' IPC.")
            elif command == "VHUSB_NOT_RUNNING":
                show_warning(f"Client {ip}:{port} reports VH USB client not running!")
                reply_str = "ACK"
            # Ignore HEARTBEAT, just let it reset timeout by being received
            elif command == "HEARTBEAT": reply_str = "ACK"
            else: log(f"[Handler:{port}] Unknown cmd: '{command}'"); reply_str = "UNKNOWN"

            # Send reply
            client_socket.sendall(reply_str.encode('utf-8'))

    # Handle disconnect/errors outside the loop
    except socket.timeout: log(f"[Handler:{port}] Client recv timed out.")
    except OSError as e: log(f"[Handler:{port}] Socket error: {e}.")
    except Exception as e: log(f"[Handler:{port}] Unexpected error: {e}.")
    finally:
        log(f"[Handler:{port}] Cleaning up connection.")
        with socket_lock:
            is_focused = False # Assume focus lost when client disconnects
            # is_client_connected = False # Let status checker handle this maybe? Or set here? Let's set here.
            # This assumes only one client matters for focus state.
        try: client_socket.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        client_socket.close()

# --- Status Checker Thread (Simplified - Only shows warning) ---
# --- Status Checker Thread (REPURPOSED: Main Loop Status Check) ---
def status_checker():
    global last_disconnect_warning_time # Still potentially used for warnings if re-enabled
    log("[Status] Status checker / Keep-Alive IPC Check thread started.")

    # Make sure POLL_INTERVAL is treated as integer
    try:
        check_interval_sec = int(POLL_INTERVAL) # Use global POLL_INTERVAL
        if check_interval_sec <= 0: check_interval_sec = 5 # Fallback if invalid
    except ValueError:
        log("[Status] Warning: Invalid POLL_INTERVAL in config, using 5s default.")
        check_interval_sec = 5

    log(f"[Status] Performing focused IPC check every {check_interval_sec}s.")

    while running:
         # Sleep for the configured interval FIRST
         time.sleep(check_interval_sec)
         if not running: break # Check flag after sleeping

         # Check if device needs re-acquiring only if focus is currently true
         with socket_lock: # Protect read of is_focused
              should_check_ipc = is_focused

         if should_check_ipc:
              # log("[Status] Checking device status while focused...") # Debug
              ipc_success, ipc_resp = send_to_ipc("DEVICE INFO")
              if ipc_success:
                  if "IN USE BY: NO ONE" in ipc_resp:
                      log("[Status] Device not in use while focused, attempting re-use...")
                      send_to_ipc("USE") # Fire and forget
                  elif "IN USE BY:" in ipc_resp and \
                       "IN USE BY: YOU" not in ipc_resp and \
                       f"IN USE BY: {DEVICE_ID}" not in ipc_resp:
                         log("[Status] Warning: Device used by other while focused.")
              # else: # Don't log IPC check failures repeatedly
              #    log("[Status] Failed IPC check while focused.")

    log("[Status] Status checker thread exiting.")


# --- Signal Handler for Ctrl+C ---
def signal_handler(sig, frame):
    global running
    log("Shutdown signal received!")
    running = False

# --- Main Server Execution ---
if __name__ == "__main__":
    # --- Setup ---
    log("Starting MouseMoveR Server...")
    if not load_config_custom(): # Use custom loader
        # Continue with defaults if possible
        pass
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # --- Start Background Threads ---
    if PROCESS_TO_KILL and HOTKEY: # Use globals directly
        threading.Thread(target=hotkey_listener, daemon=True).start()
    else: log("[Main] Hotkey disabled (PROCESS_TO_KILL or HOTKEY not set).")
    # Start the repurposed Status Checker / Focused IPC Check thread
    threading.Thread(target=status_checker, daemon=True).start()

    # --- Main Server Loop (Accept Connections) ---
    server_sock: Optional[socket.socket] = None
    try:
        server_address = ('0.0.0.0', SERVER_PORT) # Use global
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(server_address)
        server_sock.listen(5)
        log(f"Server listening on {server_address[0]}:{server_address[1]}...")

        while running:
            try:
                server_sock.settimeout(1.0) # Timeout accept to check running flag
                client_socket, client_address = server_sock.accept()
                server_sock.settimeout(None) # Remove timeout for handler

                # Start handler thread for this client
                handler_thread = threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True)
                handler_thread.start()
            except socket.timeout: continue # Loop back to check running flag
            except OSError as e:
                 if running: log(f"Server accept error: {e}")
                 break # Exit accept loop
            except Exception as e:
                 log(f"Server main loop error: {e}")
                 break

    except Exception as e:
        log(f"FATAL: Server setup error: {e}")
    finally:
        log("Server main loop exiting.")
        running = False # Signal threads
        log("Closing listening socket...")
        if server_sock: server_sock.close()
        log("Waiting briefly for threads...")
        time.sleep(0.5) # Brief pause for threads
        log("Cleanup complete. Exiting.")