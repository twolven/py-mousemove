###############################################################################
# MouseMove.exe - Client Python v4.1 FULL (Custom Config, Heartbeat, Robust)
###############################################################################

import socket
import time
import threading
import sys
import signal
import psutil # For process checking
import win32gui # For window focus
import win32process # For process checking
import ctypes # For finding window title more reliably sometimes
import os
from typing import Optional # For type hinting

# --- Global configuration (Defaults) ---
SERVER_IP = "127.0.0.1" # Default IP
SERVER_PORT = 8080
HEARTBEAT_INTERVAL = 5 # ** RE-ADDED ** Default seconds between heartbeats
POLL_INTERVAL = 2      # Seconds between focus checks / connection retries
VHUSB_CHECK_INTERVAL = 30
WINDOW_TITLE = "Breaker - Moonlight" # Default title (NOTE: This MUST match EXACTLY)
CONNECT_RETRY_DELAY = 3 # Seconds to wait after failed connection attempt

# --- Global Connection State ---
g_server_socket: Optional[socket.socket] = None
g_socket_mutex = threading.Lock()
g_is_connected = False

# --- Shutdown handling ---
running = True

# --- Helper: Logger ---
def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] [Client] {message}", flush=True)

# --- *** CUSTOM CONFIG LOADER *** ---
def load_config_custom(filename="config.txt"):
    """Loads configuration from the original key=value format file."""
    global SERVER_IP, SERVER_PORT, HEARTBEAT_INTERVAL, POLL_INTERVAL, \
           VHUSB_CHECK_INTERVAL, WINDOW_TITLE, CONNECT_RETRY_DELAY

    log(f"Attempting to load config from: {filename}")
    loaded_values = 0
    try:
        # Determine path relative to script/exe
        if getattr(sys, 'frozen', False): base_dir = os.path.dirname(sys.executable)
        else: base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, filename)

        if not os.path.exists(config_path):
             log(f"ERROR: Config file not found at '{config_path}'. Using defaults.")
             print_effective_config()
             return True # Allow running with defaults

        with open(config_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'): continue # Skip empty/comment lines
                if '=' not in line: continue # Skip lines without =

                # Use partition to handle potential '=' in value
                key, sep, value = line.partition('=')
                key = key.strip()
                value = value.strip()

                try:
                    # Client Specific Keys
                    if key == "SERVER_IP": SERVER_IP = value; loaded_values += 1
                    elif key == "SERVER_PORT": SERVER_PORT = int(value); loaded_values += 1
                    elif key == "HEARTBEAT_INTERVAL": HEARTBEAT_INTERVAL = int(value); loaded_values += 1
                    elif key == "POLL_INTERVAL": POLL_INTERVAL = int(value); loaded_values += 1
                    elif key == "VHUSB_CHECK_INTERVAL": VHUSB_CHECK_INTERVAL = int(value); loaded_values += 1
                    elif key == "CONNECT_RETRY_DELAY": CONNECT_RETRY_DELAY = int(value); loaded_values += 1
                    elif key == "WINDOW_TITLE": WINDOW_TITLE = value; loaded_values += 1
                    # Ignore known server keys silently
                    elif key in ["DEVICE_ID", "WARNING_INTERVAL", "PROCESS_TO_KILL", "HOTKEY"]: pass
                    else: log(f"Warning: Unknown config key '{key}' on line {line_num}")
                except ValueError: log(f"Warning: Invalid integer value for key '{key}' on line {line_num}: '{value}'")
                except Exception as e: log(f"Warning: Error processing config line {line_num}: {e}")

        if loaded_values > 0: log("Configuration loaded successfully.")
        else: log("Warning: No valid configuration values loaded from file. Using defaults.")
        print_effective_config()
        return True

    except Exception as e:
        log(f"ERROR loading config file '{config_path}': {e}. Using defaults.")
        print_effective_config()
        return True

def print_effective_config():
     """Prints the currently active configuration values."""
     log("Effective configuration:")
     log(f"  SERVER_IP          : {SERVER_IP}")
     log(f"  SERVER_PORT        : {SERVER_PORT}")
     log(f"  HEARTBEAT_INTERVAL : {HEARTBEAT_INTERVAL}s")
     log(f"  POLL_INTERVAL      : {POLL_INTERVAL}s")
     log(f"  VHUSB_CHECK_INTERVAL: {VHUSB_CHECK_INTERVAL}s")
     log(f"  CONNECT_RETRY_DELAY: {CONNECT_RETRY_DELAY}s")
     try: log(f"  WINDOW_TITLE       : '{WINDOW_TITLE}'")
     except UnicodeEncodeError: log(f"  WINDOW_TITLE       : (Contains non-ASCII characters)")

# --- Connect Function (Helper) ---
def establish_connection() -> bool:
    """Attempts to establish connection, returns True on success."""
    global g_server_socket, g_is_connected
    with g_socket_mutex:
        if g_server_socket: return True # Already connected
        g_is_connected = False # Ensure flag is false before attempt
        temp_socket: Optional[socket.socket] = None # Define before try block
        # log("[Net] Attempting connection...") # Less verbose
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.settimeout(3.0) # Connect/send/recv timeout
            temp_socket.connect((SERVER_IP, SERVER_PORT))
            g_server_socket = temp_socket
            g_is_connected = True # Set flag only on success
            log("[Net] Connection established.")
            return True
        except socket.timeout:
            # log("[Net] Connection timeout.")
            if temp_socket: temp_socket.close()
            return False
        except (ConnectionRefusedError, OSError) as e:
            # log(f"[Net] Connection error: {e}")
            if temp_socket: temp_socket.close()
            return False
        except Exception as e:
            log(f"[Net] Unexpected connection error: {e}")
            if temp_socket: temp_socket.close()
            return False

# --- Disconnect Function (Helper) ---
def close_connection():
    """Closes the global socket."""
    global g_server_socket, g_is_connected
    with g_socket_mutex:
        if g_server_socket:
            # log("[Net] Closing connection.") # Less verbose
            try: g_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass # Ignore errors if already closed/broken
            g_server_socket.close()
            g_server_socket = None
        g_is_connected = False # Ensure flag is false

# --- Send Command (Uses Existing Socket, Marks Invalid on Fail) ---
def send_command(command: str) -> bool:
    """Sends command, returns True on ACK, False otherwise. Handles disconnects."""
    global g_server_socket, g_is_connected
    with g_socket_mutex: # Lock for the entire operation
        if not g_server_socket: # Check socket validity inside lock
            g_is_connected = False # Ensure flag sync
            return False # Cannot send

        try:
            # log(f"[Send] Sending: {command}") # Debug
            g_server_socket.sendall(command.encode('utf-8'))
            response_bytes = g_server_socket.recv(1024) # Should block until ACK/NACK or error/timeout
            if not response_bytes: # Server closed connection gracefully after send
                 log(f"[Send] Server closed connection after command '{command}'. Marking disconnected.")
                 g_server_socket.close()
                 g_server_socket = None
                 g_is_connected = False
                 return False

            response = response_bytes.decode('utf-8')
            # log(f"[Send] Received: {response}") # Debug
            if response == "ACK":
                return True # Success
            else:
                log(f"[Send] Received non-ACK '{response}' for '{command}' (Server likely had IPC issue)")
                return False # Command wasn't fully successful server-side, but connection is likely okay.
        except socket.timeout:
            log(f"[Send] Socket timeout for '{command}'. Marking disconnected.")
            try: g_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            g_server_socket.close()
            g_server_socket = None
            g_is_connected = False
            return False
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            log(f"[Send] Socket OS error for '{command}': {e}. Marking disconnected.")
            try: g_server_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            g_server_socket.close()
            g_server_socket = None
            g_is_connected = False
            return False
        except Exception as e:
             log(f"[Send] Unexpected error for '{command}': {e}. Marking disconnected.")
             try: g_server_socket.shutdown(socket.SHUT_RDWR)
             except OSError: pass
             g_server_socket.close()
             g_server_socket = None
             g_is_connected = False
             return False

# --- Check if VirtualHere Process is Running ---
def is_process_running(process_names) -> bool:
    """Checks if any of the process names in the list are running."""
    if not isinstance(process_names, list): process_names = [process_names]
    process_names_lower = [name.lower() for name in process_names]
    try:
        for proc in psutil.process_iter(['name']):
            try:
                # Ensure proc.info['name'] exists before lowercasing
                proc_name = proc.info.get('name')
                if proc_name and proc_name.lower() in process_names_lower:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue # Ignore processes that vanished or we can't access
        return False
    except Exception as e:
        log(f"[VHCheck] Error checking processes: {e}")
        return False # Assume not running on error

# --- Monitor Window Focus (Main Logic Loop - Corrected State Update) ---
def monitor_loop():
    """Main loop checking window focus, connection, and VH process."""
    global running, g_is_connected
    log("Monitor thread started.")
    was_focused = False # Track previous focus state locally
    vh_client_names = ["vhusbdwin64.exe", "vhusbdwinw64.exe", "vhui64.exe"] # Names to check
    last_vhusb_check_time = 0 # Check immediately first time
    target_window_title_str = WINDOW_TITLE # Use global

    while running:
        # --- Connection Check & Retry ---
        if not g_is_connected:
            if not establish_connection():
                 # log(f"[Monitor] Waiting to connect... Retrying in {CONNECT_RETRY_DELAY}s...") # Less verbose
                 time.sleep(CONNECT_RETRY_DELAY) # Use specific retry delay
                 continue # Skip rest of loop, retry connection
            else: # Just reconnected
                was_focused = False # Reset internal state to force update on first check
                log("[Monitor] Reconnected. Forcing focus state update.")
                time.sleep(0.1) # Tiny pause

        # --- If Connected, Perform Checks ---
        try:
            hwnd = win32gui.FindWindow(None, target_window_title_str)
            if hwnd:
                # --- Window Found ---
                fg_hwnd = win32gui.GetForegroundWindow()
                is_now_focused = (hwnd == fg_hwnd)

                # Handle focus change - Send command ONLY if state *actually* changed
                if is_now_focused != was_focused:
                     new_state_str = "GAINED" if is_now_focused else "LOST"
                     command_to_send = "FOCUSED" if is_now_focused else "NOT_FOCUSED"
                     log(f"[Focus] Window {new_state_str} focus.")
                     # Update state FIRST
                     was_focused = is_now_focused
                     # Then send command
                     if not send_command(command_to_send):
                          log(f"[Focus] Server did not ACK '{command_to_send}'. (Continuing...)")
                          # If send failed due to disconnect, g_is_connected is now false

                # --- Periodic VHUSB Check (Only if connected)---
                current_time = time.monotonic()
                if current_time - last_vhusb_check_time > VHUSB_CHECK_INTERVAL:
                    # log("[VHCheck] Checking VirtualHere client process...") # Less verbose
                    if not is_process_running(vh_client_names):
                        log("[VHCheck] Warning: VirtualHere process not detected.")
                        send_command("VHUSB_NOT_RUNNING") # Fire and forget
                    # else: log("[VHCheck] VirtualHere client process detected.") # Less verbose
                    last_vhusb_check_time = current_time

                # Short sleep while monitoring window
                time.sleep(0.25) # Check ~4 times/sec

            else:
                # --- Window Not Found ---
                if was_focused: # If we thought it was focused, but window disappeared
                    log("[Focus] Window NOT FOUND (was focused).")
                    was_focused = False # Update state FIRST
                    if not send_command("NOT_FOCUSED"):
                        log("[Focus] Server did not ACK 'NOT_FOCUSED' (window disappeared).")
                        # If send failed due to disconnect, g_is_connected is now false

                # Sleep longer when window isn't found
                time.sleep(POLL_INTERVAL)

        except Exception as e:
            log(f"ERROR in monitor loop: {e}")
            # Consider disconnecting on certain errors? For now, just sleep.
            time.sleep(POLL_INTERVAL) # Prevent tight loop on error

    log("Monitor thread exiting.")
    close_connection() # Clean up connection when thread exits

# --- ** RE-ADDED Heartbeat Thread ** ---
def heartbeat_thread():
    """Sends heartbeats periodically to keep connection alive."""
    global running, g_is_connected
    log("[Heartbeat] Heartbeat thread started.")
    # Ensure interval is positive
    interval = max(1, HEARTBEAT_INTERVAL) # Use global, min 1 second
    log(f"[Heartbeat] Sending heartbeat every {interval}s.")
    time.sleep(interval) # Initial delay before first heartbeat

    while running:
        if g_is_connected: # Only send if we think we are connected
             # log("[Heartbeat] Sending...") # Debug
            if not send_command("HEARTBEAT"):
                log("[Heartbeat] Failed send (connection likely lost by send_command).")
                # send_command handles marking disconnected if needed
            # else: log("[Heartbeat] Sent successfully.") # Debug
        # else: log("[Heartbeat] Skipping send (disconnected).") # Debug

        # Sleep AFTER send attempt for the interval
        time.sleep(interval)
    log("[Heartbeat] Heartbeat thread exiting.")


# --- Signal Handler for Ctrl+C ---
def signal_handler(sig, frame):
    """Handles Ctrl+C or termination signals."""
    global running
    if running: # Prevent multiple calls
        log("Shutdown signal received!")
        running = False

# --- Main Execution ---
if __name__ == "__main__":
    log("Starting MouseMove Client (v4.1 - Custom Config)...")
    # Load config using custom loader
    if not load_config_custom():
        log("Proceeding with default values due to config load issue.")
        # Optionally exit if config is critical: sys.exit(1)

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start worker threads as daemons (will exit if main exits)
    log("[Main] Starting worker threads...")
    monitor = threading.Thread(target=monitor_loop, daemon=True)
    heartbeat = threading.Thread(target=heartbeat_thread, daemon=True)

    monitor.start()
    heartbeat.start()

    # Keep main thread alive while daemon threads run, exit on signal
    while running:
        try:
            time.sleep(1) # Check running flag periodically
        except KeyboardInterrupt: # Catch Ctrl+C in main thread too
             signal_handler(signal.SIGINT, None)

    log("[Main] Main loop exiting.")
    # No need to join daemon threads
    close_connection() # Final cleanup attempt
    log("Application finished.")