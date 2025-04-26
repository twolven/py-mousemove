###############################################################################
# MouseMoveR_Server.py - Server Python v4.3 (State Reconciliation Fix)
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
POLL_INTERVAL = 2 # Default POLL_INTERVAL reduced for status checker

# --- Global State ---
running = True
socket_lock = threading.Lock()
is_focused = False # <- Desired state set by client commands
is_client_connected = False # Managed by status checker / handler
last_command_time = time.monotonic()
last_disconnect_warning_time = 0

# --- Helper: Logger ---
def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] [Server] {message}", flush=True)

# --- Custom Config Loader ---
def load_config_custom(filename="config.txt"):
    """Loads configuration from the original key=value format file."""
    global DEVICE_ID, SERVER_PORT, HEARTBEAT_TIMEOUT, WARNING_INTERVAL, \
           PROCESS_TO_KILL, HOTKEY, POLL_INTERVAL

    log(f"Attempting to load config from: {filename}")
    loaded_values = 0
    config_path = filename
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
                key = key.strip(); value = value.strip()
                try:
                    # Server Specific Keys
                    if key == "DEVICE_ID": DEVICE_ID = value; loaded_values += 1
                    elif key == "SERVER_PORT": SERVER_PORT = int(value); loaded_values += 1
                    elif key == "HEARTBEAT_TIMEOUT": HEARTBEAT_TIMEOUT = int(value); loaded_values += 1
                    elif key == "WARNING_INTERVAL": WARNING_INTERVAL = int(value); loaded_values += 1
                    elif key == "PROCESS_TO_KILL": PROCESS_TO_KILL = value; loaded_values += 1
                    elif key == "HOTKEY": HOTKEY = value; loaded_values += 1
                    elif key == "POLL_INTERVAL": POLL_INTERVAL = int(value); loaded_values += 1
                    # Ignore known client keys silently
                    elif key in ["SERVER_IP", "VHUSB_CHECK_INTERVAL", "WINDOW_TITLE", "CONNECT_RETRY_DELAY", "HEARTBEAT_INTERVAL"]: pass
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
        return True # Allow running with defaults

def print_effective_config():
     """Prints the currently active configuration values."""
     log("Effective configuration:")
     log(f"  DEVICE_ID        : {DEVICE_ID}")
     log(f"  SERVER_PORT      : {SERVER_PORT}")
     log(f"  HEARTBEAT_TIMEOUT: {HEARTBEAT_TIMEOUT}s (Since last command)")
     log(f"  WARNING_INTERVAL : {WARNING_INTERVAL}s")
     log(f"  POLL_INTERVAL    : {POLL_INTERVAL}s (Status/Sync Interval)")
     log(f"  PROCESS_TO_KILL  : '{PROCESS_TO_KILL or '[Not Set]'}'")
     log(f"  HOTKEY           : '{HOTKEY or '[Not Set]'}'")


# --- SendToIPC ---
def send_to_ipc(command: str) -> tuple[bool, str, Optional[int]]:
    """Sends command to VirtualHere pipe, returns (success, response_str, winerror_or_none)."""
    pipe_name = r'\\.\pipe\vhclient'; full_command = command
    # Auto-append device ID for relevant commands if needed
    if command in ["USE", "STOP USING", "DEVICE INFO"] and DEVICE_ID not in command:
        full_command = f"{command},{DEVICE_ID}"
    elif DEVICE_ID not in command and command.upper().startswith(("USE,", "STOP USING,", "DEVICE INFO,")):
        pass # Assume already formatted if comma present but ID missing
    elif DEVICE_ID not in command and command not in ["LIST"]:
         pass # Avoid appending ID to LIST or unknown commands

    try:
        # log(f"IPC Send: {full_command}") # Very verbose debug
        handle = win32file.CreateFile(pipe_name, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None)
        # Set pipe mode? Might not be needed. win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, full_command.encode('utf-8'))
        # Read response (may block, timeout set on pipe properties or via ReadFileEx usually)
        hr, resp_bytes = win32file.ReadFile(handle, 4096); response = resp_bytes.decode('utf-8', errors='ignore').strip()
        win32file.CloseHandle(handle);
        # log(f"IPC Recv: {response}") # Very verbose debug
        return True, response, None
    except pywintypes.error as e:
        # Only log unexpected errors, not "file not found" (error 2)
        if e.winerror != 2: log(f"[IPC] pywintypes error {e.winerror} for '{full_command}': {e.strerror}")
        return False, "", e.winerror
    except Exception as e: log(f"[IPC] Unexpected error for '{full_command}': {e}"); return False, "", -1


# --- Warning Message Display ---
def show_warning(message: str):
    """Shows a warning message box in a separate thread."""
    log(f"Showing Warning: {message}")
    threading.Thread(target=ctypes.windll.user32.MessageBoxW, args=(0, message, "MouseMoveR Warning", 0x30 | 0x1000), daemon=True).start()


# --- Process Killing Function ---
def find_and_kill_process():
    """Finds and terminates the configured process."""
    if not PROCESS_TO_KILL: log("[Kill] Hotkey ignored: Not configured."); return
    log(f"[Kill] Hotkey! Searching for '{PROCESS_TO_KILL}'..."); p_lower = PROCESS_TO_KILL.lower(); found = 0; killed = 0
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pinfo = proc.info
                # Check if name exists before lowercasing
                proc_name = pinfo.get('name')
                if proc_name and proc_name.lower() == p_lower:
                    found += 1; log(f"  [+] Found PID: {pinfo['pid']} ({pinfo['name']})"); p = psutil.Process(pinfo['pid'])
                    try:
                        log(f"      Terminating..."); p.terminate(); p.wait(1); log(f"      Terminated."); killed += 1
                    except psutil.TimeoutExpired:
                        log(f"      Timeout, killing..."); p.kill(); p.wait(0.5); log(f"      Killed."); killed += 1
                    except psutil.NoSuchProcess: log(f"      Gone."); killed += 1 # Count as killed if it disappeared
                    except psutil.AccessDenied: log(f"      Access Denied (Run as Admin?).")
                    except Exception as te: log(f"      Error killing PID {pinfo['pid']}: {te}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue # Skip processes we can't access
        if not found: log(f"[Kill] Process not found.")
        else: log(f"[Kill] Done. Found:{found}, Killed:{killed}.")
    except Exception as e: log(f"[Kill] Error iterating processes: {e}")


# --- Hotkey Listener Thread ---
def hotkey_listener():
    """Listens for the configured hotkey using the 'keyboard' library."""
    if not HOTKEY: log("[Hotkey] Disabled."); return
    hotkey_norm = HOTKEY.replace('\\', 'backslash') # Normalize common name
    # Add more normalizations if needed: .replace('control', 'ctrl'), etc.
    log(f"[Hotkey] Starting listener for key: '{hotkey_norm}'...")
    try:
        # suppress=False is usually better for game compatibility if it works
        keyboard.add_hotkey(hotkey_norm, find_and_kill_process, suppress=False, trigger_on_release=False)
        log(f"[Hotkey] Listener registered for '{hotkey_norm}'.")
        while running: time.sleep(1) # Keep thread alive while checking running flag
    except ImportError: log("[Hotkey] ERROR: 'keyboard' library not installed (pip install keyboard).")
    except Exception as e: log(f"[Hotkey] ERROR setup: {e} (Try Run as Admin?)")

    log("[Hotkey] Listener thread exiting.")
    try:
        keyboard.remove_all_hotkeys() # Attempt cleanup
    except Exception:
        pass # Ignore errors during cleanup


# --- Persistent Client Connection Handling (State Update Only) ---
def handle_client(client_socket: socket.socket, address: tuple):
    """Handles commands, updates global state, ACKs client."""
    global is_focused, is_client_connected, last_command_time # Allow modification
    ip, port = address; log(f"[Handler:{port}] Connection from {ip}:{port}")
    recv_timeout = HEARTBEAT_TIMEOUT + 5; client_socket.settimeout(recv_timeout)
    client_had_focus_at_disconnect = False # Track if focus was true when this specific client disconnects

    try:
        # Mark connected immediately when handler starts for this client
        # Note: Multiple clients could connect, is_client_connected tracks if *any* are active
        with socket_lock: is_client_connected = True; last_command_time = time.monotonic()

        while running: # Loop receiving commands
            data = client_socket.recv(1024);
            if not data: log(f"[Handler:{port}] Client disconnected."); break # Exit loop

            command = data.decode('utf-8', errors='ignore').strip();
            if not command: continue # Ignore empty messages

            log(f"[Handler:{port}] Rcvd: '{command}'")

            # --- Update global state on ANY valid command received ---
            with socket_lock:
                is_client_connected = True # Keep alive status
                last_command_time = time.monotonic() # Update last activity time

                # --- ONLY UPDATE STATE, DO NOT CALL IPC for FOCUS changes ---
                if command == "FOCUSED":
                    if not is_focused: # Only log the change
                         log(f"[State Update] Desired focus state changed to: True")
                    is_focused = True
                    client_had_focus_at_disconnect = True # Track this client's last focus state
                elif command == "NOT_FOCUSED":
                     if is_focused: # Only log the change
                          log(f"[State Update] Desired focus state changed to: False")
                     is_focused = False
                     client_had_focus_at_disconnect = False
                # Handle VHUSB warning immediately
                elif command == "VHUSB_NOT_RUNNING":
                    show_warning(f"Client {ip}:{port} reports VH client not running!")
                # HEARTBEAT just updates the last_command_time (done above)

            # --- ALWAYS SEND ACK if command is known ---
            reply = "ACK" # Assume ACK unless it was truly unknown
            if command not in ["FOCUSED", "NOT_FOCUSED", "VHUSB_NOT_RUNNING", "HEARTBEAT"]:
                 log(f"[Handler:{port}] Unknown cmd: '{command}'")
                 reply = "UNKNOWN"

            # Send the reply
            try:
                 client_socket.sendall(reply.encode('utf-8'))
            except OSError as send_err:
                 log(f"[Handler:{port}] Send ACK failed: {send_err}.")
                 break # Exit loop if we can't even send ACK

    except socket.timeout: log(f"[Handler:{port}] Client recv timed out (> {recv_timeout}s).")
    except OSError as e: log(f"[Handler:{port}] Socket error: {e}.")
    except Exception as e: log(f"[Handler:{port}] Unexpected error: {e}.")
    finally:
        log(f"[Handler:{port}] Cleaning up connection.")
        # Failsafe check: If this specific client disconnected and it was the one that last set focus=True,
        # ensure the global desired state is set back to False.
        if client_had_focus_at_disconnect:
             log(f"[Handler:{port}] Client disconnected while it had focus flag. Forcing desired state to False.")
             with socket_lock:
                  is_focused = False # Ensure desired state doesn't get stuck on True
        # Close socket
        try: client_socket.shutdown(socket.SHUT_RDWR); client_socket.close()
        except OSError: pass
        # Note: We don't set is_client_connected = False here. The status_checker handles that based on timeout.


# --- Status Checker Thread (Includes State Reconciliation) ---
def status_checker():
    """Periodically checks client timeout and reconciles focus state with IPC."""
    global is_client_connected, is_focused, last_command_time, last_disconnect_warning_time
    log("[Status] Status checker thread started."); check_interval = max(1, POLL_INTERVAL)
    log(f"[Status] Performing checks every {check_interval}s.")

    while running:
        time.sleep(check_interval);
        if not running: break
        now = time.monotonic(); disconnected_on_this_cycle = False

        # 1. Check Client Timeout
        current_desired_focus = False # Default desired state if disconnected
        client_should_be_connected = False
        with socket_lock: # Read shared state safely
            client_should_be_connected = is_client_connected # Cache current state
            current_desired_focus = is_focused if is_client_connected else False # Cache desired state

            if client_should_be_connected and (now - last_command_time > HEARTBEAT_TIMEOUT):
                log(f"[Status] Client timed out ({HEARTBEAT_TIMEOUT}s). Marking disconnected.")
                is_client_connected = False; is_focused = False; # Reset state
                current_desired_focus = False # Update cached desired state
                client_should_be_connected = False # Update cached connection state
                disconnected_on_this_cycle = True
                last_disconnect_warning_time = 0 # Show warning soon

        # 2. Show Disconnect Warning (if needed)
        if not client_should_be_connected and (now - last_disconnect_warning_time > WARNING_INTERVAL):
             if not disconnected_on_this_cycle: # Don't warn immediately after timeout
                  show_warning("No connection from MouseMove client.");
             last_disconnect_warning_time = now # Reset timer after showing/checking

        # 3. Reconcile Focus State with IPC
        # Check IPC regardless of client connection? No, only if we *expect* focus based on client
        # But if client disconnected while focused, we need to STOP USING.
        # Therefore, check IPC state, then decide action based on desired_focus.

        # log("[Status] Checking IPC device state...") # Very verbose debug
        ipc_success, ipc_response, ipc_err = send_to_ipc("DEVICE INFO")
        if ipc_success:
            # Determine current IPC state ("in use" vs "not in use")
            # Using simpler logic: Assume "in use" if the response does NOT contain "NO ONE"
            current_ipc_state_in_use = ("IN USE BY: NO ONE" not in ipc_response)
            # log(f"[Status] IPC State: {'In Use' if current_ipc_state_in_use else 'Not In Use'}. Desired State: {'Focus' if current_desired_focus else 'No Focus'}") # Debug

            # Compare desired state (current_desired_focus) with actual IPC state
            if current_desired_focus and not current_ipc_state_in_use:
                # We want focus, but device is idle -> Send USE
                log("[Status] State Sync: Desired=Focus, Actual=Idle. Sending USE...")
                send_to_ipc("USE")
            elif not current_desired_focus and current_ipc_state_in_use:
                # We don't want focus, but device is in use -> Send STOP USING
                log("[Status] State Sync: Desired=No Focus, Actual=In Use. Sending STOP USING...")
                send_to_ipc("STOP USING")
            # else: States match, do nothing.

        elif ipc_err != 2: # Log IPC errors other than "VH client not running"
            log("[Status] Failed to get DEVICE INFO from IPC to check state.")
        # else: VH client likely not running, cannot reconcile.

    log("[Status] Status checker thread exiting.")


# --- Signal Handler ---
def signal_handler(sig, frame):
    """Sets the running flag to False on Ctrl+C or termination signals."""
    global running;
    if running: # Prevent multiple logs if signal received multiple times
        log("Shutdown signal received!"); running = False

# --- Main Server Execution ---
if __name__ == "__main__":
    log("Starting MouseMoveR Server (v4.3 - State Reconciliation)...")
    # Load config using the custom key=value loader
    if not load_config_custom():
        pass # Continue with defaults if loading fails

    # Setup signal handlers for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start background threads as daemons (won't prevent exit if main terminates)
    if PROCESS_TO_KILL and HOTKEY:
        threading.Thread(target=hotkey_listener, daemon=True).start()
    else:
        log("[Main] Hotkey feature disabled (PROCESS_TO_KILL or HOTKEY not set).")
    threading.Thread(target=status_checker, daemon=True).start()

    # --- Main Server Loop (Accept Connections) ---
    server_sock: Optional[socket.socket] = None
    try:
        server_address = ('0.0.0.0', SERVER_PORT) # Listen on all interfaces
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow quick restart
        server_sock.bind(server_address)
        server_sock.listen(5) # Queue up to 5 connections
        log(f"Server listening on {server_address[0]}:{server_address[1]}...")

        while running: # Main accept loop, check running flag
            try:
                # Use timeout on accept to allow checking the running flag periodically
                server_sock.settimeout(1.0)
                client_socket, client_address = server_sock.accept()
                server_sock.settimeout(None) # Remove timeout for the client handler socket

                # Start a persistent handler thread for the new client
                handler_thread = threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True)
                handler_thread.start()

            except socket.timeout:
                continue # No connection attempt, just check 'running' flag and loop
            except OSError as e:
                # If accept fails and we are trying to shut down, that's expected
                if running: log(f"Server accept error: {e}")
                break # Exit accept loop on unexpected error
            except Exception as e:
                 log(f"Server main loop error: {e}")
                 break # Exit accept loop

    except Exception as e:
        log(f"FATAL: Server setup error (bind/listen?): {e}")
    finally:
        log("Server main loop exiting."); running = False # Signal threads again
        log("Closing listening socket...");
        if server_sock: server_sock.close()
        log("Waiting briefly for threads to notice shutdown..."); time.sleep(0.5)
        log("Cleanup complete. Exiting.")