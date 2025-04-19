###############################################################################
# MouseMove.exe - Client Python v3.0 (Custom Config, Simplified Persistent)
###############################################################################

import socket
import time
import threading
import sys
import signal
import psutil # For process checking
import win32gui # For window focus
import win32process # For process checking (alternative if psutil fails)
import ctypes # For finding window title more reliably sometimes
import os
from typing import Optional # For type hinting

# --- Global configuration (Defaults) ---
SERVER_IP = "127.0.0.1" # Default IP
SERVER_PORT = 8080
POLL_INTERVAL = 2
VHUSB_CHECK_INTERVAL = 30
WINDOW_TITLE = "Breaker - Moonlight" # Default title (NOTE: This MUST match EXACTLY)

# --- Global Connection State ---
g_server_socket: Optional[socket.socket] = None
g_socket_mutex = threading.Lock()
g_is_connected = False

# --- Shutdown handling ---
running = True

# --- Helper: Logger ---
def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] [Client] {message}", flush=True)

# --- CUSTOM CONFIG LOADER ---
def load_config_custom(filename="config.txt"):
    """Loads configuration from the original format file into global variables."""
    global SERVER_IP, SERVER_PORT, POLL_INTERVAL, VHUSB_CHECK_INTERVAL, WINDOW_TITLE

    log(f"Attempting to load config from: {filename}")
    try:
        # Determine path relative to script/exe
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, filename)

        if not os.path.exists(config_path):
             log(f"ERROR: Config file not found at '{config_path}'. Using defaults.")
             print_effective_config() # Show defaults being used
             return True # Allow running with defaults

        with open(config_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue # Skip empty/comment lines

                if '=' not in line:
                    log(f"Warning: Skipping invalid line {line_num} in config: '{line}' (missing '=')")
                    continue

                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                try:
                    if key == "SERVER_IP": SERVER_IP = value
                    elif key == "SERVER_PORT": SERVER_PORT = int(value)
                    elif key == "POLL_INTERVAL": POLL_INTERVAL = int(value)
                    elif key == "VHUSB_CHECK_INTERVAL": VHUSB_CHECK_INTERVAL = int(value)
                    elif key == "WINDOW_TITLE": WINDOW_TITLE = value # Store as string
                    # Ignore server-specific keys if present
                    elif key in ["DEVICE_ID", "HEARTBEAT_TIMEOUT", "WARNING_INTERVAL", "PROCESS_TO_KILL", "HOTKEY"]:
                        pass
                    else:
                         log(f"Warning: Unknown config key '{key}' on line {line_num}")
                except ValueError:
                    log(f"Warning: Invalid integer value for key '{key}' on line {line_num}: '{value}'")
                except Exception as e:
                    log(f"Warning: Error processing config line {line_num}: {e}")

        log("Configuration loaded successfully.")
        print_effective_config()
        return True

    except Exception as e:
        log(f"ERROR loading config file '{config_path}': {e}")
        log("Using default values.")
        print_effective_config()
        return True # Allow running with defaults

def print_effective_config():
     """Prints the currently active configuration values."""
     # Note: WINDOW_TITLE might be unicode, handle printing carefully if issues arise
     log("Effective configuration:")
     log(f"  SERVER_IP          : {SERVER_IP}")
     log(f"  SERVER_PORT        : {SERVER_PORT}")
     log(f"  POLL_INTERVAL      : {POLL_INTERVAL}s")
     log(f"  VHUSB_CHECK_INTERVAL: {VHUSB_CHECK_INTERVAL}s")
     try:
         log(f"  WINDOW_TITLE       : '{WINDOW_TITLE}'")
     except UnicodeEncodeError:
          log(f"  WINDOW_TITLE       : (Contains non-ASCII characters)")


# --- Connect Function (Helper) ---
def establish_connection() -> bool:
    global g_server_socket, g_is_connected
    with g_socket_mutex:
        if g_server_socket: return True # Already connected
        g_is_connected = False
        # log("[Net] Attempting connection...") # Less verbose
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.settimeout(3.0) # Connect/send/recv timeout
            temp_socket.connect((SERVER_IP, SERVER_PORT))
            g_server_socket = temp_socket
            g_is_connected = True
            log("[Net] Connection established.")
            return True
        except socket.timeout:
            # log("[Net] Connection timeout.") # Less verbose
            return False
        except (ConnectionRefusedError, OSError) as e:
            # log(f"[Net] Connection error: {e}") # Less verbose
            if temp_socket: temp_socket.close()
            return False
        except Exception as e:
            log(f"[Net] Unexpected connection error: {e}")
            if temp_socket: temp_socket.close()
            return False

# --- Disconnect Function (Helper) ---
def close_connection():
    global g_server_socket, g_is_connected
    with g_socket_mutex:
        if g_server_socket:
            log("[Net] Closing connection.")
            try: g_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            g_server_socket.close()
            g_server_socket = None
        g_is_connected = False

# --- Send Command (Simplified - Uses Existing Socket, Marks Invalid on Fail) ---
def send_command(command: str) -> bool:
    global g_server_socket, g_is_connected
    with g_socket_mutex:
        if not g_server_socket:
            g_is_connected = False
            return False # Cannot send
        try:
            # log(f"[Send] Sending: {command}") # Debug
            g_server_socket.sendall(command.encode('utf-8'))
            response = g_server_socket.recv(1024).decode('utf-8')
            # log(f"[Send] Received: {response}") # Debug
            if response == "ACK":
                return True
            else:
                log(f"[Send] Received non-ACK '{response}' for '{command}'")
                return False # Treat as failure, but keep connection for now
        except (socket.timeout, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            log(f"[Send] Socket error for '{command}': {e}. Marking disconnected.")
            try: g_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            g_server_socket.close()
            g_server_socket = None
            g_is_connected = False
            return False
        except Exception as e:
             log(f"[Send] Unexpected send/recv error for '{command}': {e}. Marking disconnected.")
             try: g_server_socket.shutdown(socket.SHUT_RDWR)
             except OSError: pass
             g_server_socket.close()
             g_server_socket = None
             g_is_connected = False
             return False

# --- Check if VirtualHere Process is Running ---
def is_process_running(process_names) -> bool:
    if not isinstance(process_names, list): process_names = [process_names]
    process_names_lower = [name.lower() for name in process_names]
    try:
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() in process_names_lower: return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
        return False
    except Exception as e: log(f"[VHCheck] Error checking processes: {e}"); return False

# --- Monitor Window Focus (Main Logic Loop - Simplified) ---
# --- Monitor Window Focus (Main Logic Loop - CORRECTED SPAM FIX) ---
def monitor_loop():
    global running, g_is_connected
    log("Monitor thread started.")
    was_focused = False # Track previous focus state locally
    hwnd = None # Initialize hwnd

    # Attempt initial connection before loop (optional but cleaner)
    if not g_is_connected:
        establish_connection()

    while running:
        # --- Connection Check & Retry ---
        if not g_is_connected:
            if not establish_connection():
                 # log(f"[Monitor] Waiting to connect... Retrying in {POLL_INTERVAL}s...") # Less verbose
                 time.sleep(POLL_INTERVAL)
                 continue # Skip rest of loop, retry connection
            else:
                # Just reconnected, reset focus state to force update
                was_focused = False # <-- Reset state on successful REconnect
                log("[Monitor] Reconnected. Forcing focus state update.")

        # --- If Connected, Perform Checks ---
        try:
            # Find window using the configured title
            target_window_title = WINDOW_TITLE # Get potentially updated title (if config reloaded?)
            hwnd = win32gui.FindWindow(None, target_window_title)

            if hwnd:
                # --- Window Found ---
                fg_hwnd = win32gui.GetForegroundWindow()
                is_now_focused = (hwnd == fg_hwnd)

                # --- Handle Focus Change ---
                # Compare current state with previous state
                if is_now_focused and not was_focused:
                    log("[Focus] Window GAINED focus.")
                    was_focused = True # <<< UPDATE STATE *BEFORE* SENDING
                    if not send_command("FOCUSED"):
                        # Log failure, but state is already updated
                        log("[Focus] Server did not ACK 'FOCUSED' (IPC likely failed server-side).")
                        # g_is_connected might be false now, handled next loop

                elif not is_now_focused and was_focused:
                    log("[Focus] Window LOST focus.")
                    was_focused = False # <<< UPDATE STATE *BEFORE* SENDING
                    if not send_command("NOT_FOCUSED"):
                        # Log failure, but state is already updated
                        log("[Focus] Server did not ACK 'NOT_FOCUSED'.")
                        # g_is_connected might be false now, handled next loop

                # --- Periodic VHUSB Check (Only when connected and window found) ---
                # (Keep this logic the same as before)
                current_time = time.monotonic()
                # Initialize check time if needed (avoids immediate check after reconnect)
                if 'last_vhusb_check_time' not in locals(): last_vhusb_check_time = current_time
                if current_time - last_vhusb_check_time > VHUSB_CHECK_INTERVAL:
                    log("[VHCheck] Checking VirtualHere client process...")
                    vh_client_names = ["vhusbdwin64.exe", "vhusbdwinw64.exe", "vhui64.exe"]
                    if not is_process_running(vh_client_names):
                        log("[VHCheck] Warning: VirtualHere process not detected.")
                        send_command("VHUSB_NOT_RUNNING") # Fire and forget
                    else:
                        log("[VHCheck] VirtualHere client process detected.")
                    last_vhusb_check_time = current_time

                # Short sleep while monitoring window
                time.sleep(0.25) # Check ~4 times/sec

            else:
                # --- Window Not Found ---
                if was_focused:
                    log("[Focus] Window NOT FOUND (was focused).")
                    was_focused = False # <<< UPDATE STATE *BEFORE* SENDING
                    if not send_command("NOT_FOCUSED"):
                        log("[Focus] Server did not ACK 'NOT_FOCUSED' (window not found).")
                        # g_is_connected might be false now, handled next loop

                # Sleep longer when window isn't found
                time.sleep(POLL_INTERVAL)

        except Exception as e:
            log(f"ERROR in monitor loop: {e}")
            # Prevent tight loop on persistent error
            # Consider closing connection if error seems network related?
            # For now, just sleep.
            time.sleep(POLL_INTERVAL)

    log("Monitor thread exiting.")
    close_connection() # Clean up connection


# --- Signal Handler for Ctrl+C ---
def signal_handler(sig, frame):
    global running
    log("Shutdown signal received!")
    running = False

# --- Main Execution ---
if __name__ == "__main__":
    # --- Setup ---
    log("Starting MouseMove Client...")
    if not load_config_custom(): # Use the custom loader
        log("Exiting due to config load issue (see above).")
        # Default values might have been used, decide if exit is necessary
        # sys.exit(1) # Uncomment if config is mandatory
        pass # Continue with defaults if possible

    signal.signal(signal.SIGINT, signal_handler) # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # Handle termination signal

    # --- Start the main loop (no separate threads needed for this simple version) ---
    monitor_loop()

    log("Application finished.")