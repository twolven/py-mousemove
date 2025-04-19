# MouseMove (Python Version)

## Why Use This Program?

MouseMove solves a specific problem encountered with remote desktop software (like Moonlight, Parsec) and certain applications (often games): some programs require direct USB input and reject simulated mouse movements common in remote scenarios.

VirtualHere is an excellent solution for sharing USB devices over your network, but manually connecting/disconnecting devices every time you switch focus between your local machine and the remote stream is tedious.

This project automates the process:
1.  **MouseMove Client (`MouseMove.exe`)**: Runs on your local PC where you start the stream (e.g., Moonlight). It monitors which window has focus.
2.  **MouseMove Server (`MouseMoveR.exe`)**: Runs on the remote PC (the one hosting the game/application and connected to the VirtualHere USB Server). It listens for commands from the client.

When you focus the specified streaming window (e.g., Moonlight), the client tells the server, and the server automatically tells VirtualHere (via its command-line/pipe interface) to "use" your shared USB device (like a mouse or controller). When you focus away, the client tells the server to release the device.

This provides seamless switching without manual VirtualHere interaction, ideal for:
*   Gaming setups using Moonlight/Sunshine/Parsec where direct input is needed.
*   Remote workstations requiring precise input devices.
*   Applications that reject simulated input.
*   Setups where you frequently switch between local and remote use.

**(New in Python Version):** Includes a server-side hotkey to quickly terminate a specified process (useful for closing hung games/apps).

## Features

-   Automatically connects/disconnects a specified VirtualHere USB device based on window focus on the client machine.
-   Monitors a specific window title (configurable) for focus changes.
-   Uses **persistent TCP connections** for reliable communication.
-   Client periodically checks if the remote VirtualHere USB Server process (`vhusbdwin64.exe`, etc.) is running and warns the server if it's not found.
-   Server includes a **configurable hotkey** (using polling for better game compatibility) to terminate a specified process on the server machine.
-   All settings are configurable via a simple `config.txt` file (compatible with the original C++ version's format).
-   Provides server-side pop-up warnings for specific issues (like VHUSB Server not detected by client).

## Requirements

-   **Operating System:** Windows (due to `pywin32`, `keyboard`, `ctypes` usage for window monitoring, IPC, hotkeys, and process checking).
-   **Python:** Python 3.7+ (for development/building from source). The packaged EXE includes its own Python runtime.
-   **Python Libraries (for building/running from source):** `psutil`, `pywin32`, `keyboard`
-   **VirtualHere:**
    -   VirtualHere USB Client installed on the remote machine (where `MouseMoveR.exe` runs).
    -   VirtualHere USB Server (`vhusbdwin64.exe` or similar) running on the machine physically connected to the USB device you want to share (can be the same as the remote machine or different).
-   **Network:** LAN or VLAN connectivity between the Client and Server machines.

## Installation Guide

1.  Download `MouseMove.exe` (Client) and `MouseMoveR.exe` (Server) from the latest release on GitHub.
2.  Create **one** `config.txt` file in the **same directory** where you place **both** executables. *Note: Both executables read the same file but use different settings from it.*

    **Example `config.txt`:**
    ```ini
    # MouseMove & MouseMoveR Configuration
    # NO section headers like [Client] or [Server] needed!

    # --- Settings Used by Client (MouseMove.exe) ---
    SERVER_IP = 192.168.1.101     # IP ADDRESS of the computer running MouseMoveR.exe
    # SERVER_PORT is shared, see below
    POLL_INTERVAL = 2             # Seconds client waits between focus checks (if window not found)
    VHUSB_CHECK_INTERVAL = 30     # Seconds between client checks if vhusbdwin64.exe is running on its own machine
    WINDOW_TITLE = YourPCName - Moonlight  # EXACT Window Title of your streaming application (Case Sensitive!)

    # --- Settings Used by Server (MouseMoveR.exe) ---
    DEVICE_ID = YOUR_VH_DEVICE_ID # e.g., GWire.126 or ServerName.1234 - Find in VirtualHere Client UI
    SERVER_PORT = 8080            # Port the server listens on (must match client)
    WARNING_INTERVAL = 60         # Seconds between showing "Client disconnected" warnings
    PROCESS_TO_KILL = Game.exe    # EXACT Process name (like in Task Manager Details) to kill with hotkey
    HOTKEY = \                    # Hotkey to kill the process (e.g., \ for backslash)
    ```

3.  **Configure `config.txt`:**
    *   Replace `192.168.1.101` with the actual IP address of the computer that will run `MouseMoveR.exe`.
    *   Replace `YourPCName - Moonlight` with the **exact** window title of your streaming application as it appears in the Windows title bar.
    *   Replace `YOUR_VH_DEVICE_ID` with the specific address/ID of the USB device you want to control (find this in the VirtualHere Client window - it looks like `ServerName.DeviceID` or `IPAddress.DeviceID`).
    *   Replace `Game.exe` with the target process for the kill hotkey. Leave blank (`PROCESS_TO_KILL = `) to disable.
    *   Change `HOTKEY = \` if desired (only `\` is guaranteed to work well with games via polling currently). Leave blank (`HOTKEY = `) to disable.
    *   Ensure `SERVER_PORT` matches on both sides (8080 is usually fine). Adjust other intervals if needed.

4.  **Run the Server (`MouseMoveR.exe`):**
    *   Place `MouseMoveR.exe` and the configured `config.txt` on the **remote computer** (the one receiving the stream and controlling VirtualHere Client).
    *   **IMPORTANT:** Right-click `MouseMoveR.exe` and select **"Run as administrator"**. This is required for the hotkey and process killing features to work reliably.
    *   Allow it through the Windows Firewall if prompted.

5.  **Run the Client (`MouseMove.exe`):**
    *   Place `MouseMove.exe` and the **same** configured `config.txt` on the **local computer** (the one you are physically using and launching the stream from).
    *   Double-click `MouseMove.exe` to run it. It will run in the background (no console window by default). To stop it, use Task Manager to end the `MouseMove.exe` process or press Ctrl+C if you ran it from a console.

## Troubleshooting

*   **No Connection:**
    *   Verify `SERVER_IP` and `SERVER_PORT` match in `config.txt` and that the server is actually running.
    *   Check Windows Firewall settings on *both* computers allow the executables (or the specific port).
    *   Ensure both PCs are on the same network and can ping each other.
*   **Focus Not Detected / Device Not Switching:**
    *   Double-check the `WINDOW_TITLE` in `config.txt`. It must be **exactly** the same as the title bar of the streaming window, including capitalization and spacing.
    *   Ensure only one instance of the client (`MouseMove.exe`) is running.
*   **Device Not Controlled / Server Errors:**
    *   Verify the `DEVICE_ID` in `config.txt` exactly matches the device address shown in the VirtualHere Client UI running on the *server* machine.
    *   Make sure the **VirtualHere Client** application is running on the *server* machine. `MouseMoveR.exe` talks to the VH Client via its pipe interface.
*   **Hotkey Not Killing Process:**
    *   Ensure `MouseMoveR.exe` is running **as Administrator**.
    *   Verify the `PROCESS_TO_KILL` name in `config.txt` exactly matches the executable name in Task Manager (Details tab).
*   **Client/Server Closes Immediately or Doesn't Start:**
    *   Build/run the `--console` version (see below) to check for error messages.
    *   Ensure `config.txt` is present in the same directory as the `.exe`.
    *   Check if Antivirus is interfering.

## Building from Source

If you want to build the executables yourself:

1.  **Install Prerequisites:**
    *   Python 3.7+ (ensure `python` and `pip` are in your system PATH).
    *   Git (for cloning).
2.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(You'll need to create a `requirements.txt` file containing:*
    ```
    psutil
    pywin32
    keyboard
    pyinstaller
    ```
    *Note: `pyinstaller` is only needed for building the EXE, not running the `.py` scripts directly).*
4.  **Build with PyInstaller:**
    *   Open `cmd` or `PowerShell` in the repository directory.
    *   **Client (Console Version for Debugging):**
        ```bash
        pyinstaller --onefile --console --name MouseMove --hidden-import=win32timezone mousemove_client.py
        ```
    *   **Client (Windowed Version for Release):**
        ```bash
        pyinstaller --onefile --windowed --name MouseMove --icon=client.ico --hidden-import=win32timezone mousemove_client.py
        ```
    *   **Server (Console Version for Debugging):**
        ```bash
        pyinstaller --onefile --console --name MouseMoveR --hidden-import=win32timezone --hidden-import=win32pipe --hidden-import=win32file --hidden-import=pywintypes mousemover_server.py
        ```
    *   **Server (Windowed Version for Release):**
        ```bash
        pyinstaller --onefile --windowed --name MouseMoveR --icon=server.ico --hidden-import=win32timezone --hidden-import=win32pipe --hidden-import=win32file --hidden-import=pywintypes mousemover_server_v3.py
        ```
    *   *(Add `--icon=your_icon.ico` if you have icon files).*
    *   *(Add more `--hidden-import` flags if PyInstaller misses modules during the build - check build logs).*
5.  **Output:** The executables (`MouseMove.exe`, `MouseMoveR.exe`) will be in the `dist` sub-folder. Remember to copy `config.txt` alongside them.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the Branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## Support

For issues and feature requests, please use the GitHub issues system for this repository.