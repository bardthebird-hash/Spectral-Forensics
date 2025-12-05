SPECTRAL // FORENSICS

Spectral Forensics is an enterprise-grade digital forensics framework designed with a cyberpunk aesthetic for Nobara Linux and other Linux distributions. It runs entirely in the terminal (TUI), providing a "Super Computer" feel while offering robust tools for live system monitoring, artifact analysis, and case reporting.

⚡ Features

🖥️ Cyberpunk TUI: Built with Textual for a responsive, mouse-compatible terminal interface.

📂 Artifact Inspector: View file metadata, hex dumps, and extract strings.

🔍 Forensic Hashing: Calculate MD5 and SHA256 hashes for file integrity verification.

📡 Live Network Monitor: Real-time tracking of active TCP/UDP connections and associated PIDs.

⚙️ Process Watcher: Live table of running processes, sorted by memory usage.

🔐 Remote Uplink (SSH): Built-in SSH client to execute commands on remote/headless targets.

📄 Evidence Locker & Reporting: Tag artifacts during analysis and export a professional PDF case report.

🛠️ Installation

Spectral Forensics requires Python 3.8+. It is recommended to run this on a Linux system (Nobara, Fedora, Ubuntu, Kali, etc.).

1. Clone the Repository

git clone [https://github.com/yourusername/spectral-forensics.git](https://github.com/yourusername/spectral-forensics.git)
cd spectral-forensics

1.5. This system is built to work with venv and pip. Run venv with:
python3 -m venv [name of project]
source [name of project]/bin/activate


2. Install Dependencies

Install the required Python libraries using pip.

pip install textual psutil rich paramiko fpdf2


textual: The TUI framework.

psutil: For system monitoring (CPU, RAM, Network, Processes).

rich: For advanced text formatting.

paramiko: For the SSH Remote Uplink.

fpdf2: For generating PDF case reports.

🚀 Usage

To launch the system, simply run the python script from your terminal.

python spectral_forensics.py


Tip: For the best experience, maximize your terminal window or press F11 for full-screen mode.

⌨️ Controls

Mouse: Full mouse support. Click tabs, buttons, and files.

q: Quit the application.

d: Toggle Dark/Light mode (Default is Dark/Cyberpunk).

⚠️ Disclaimer

This tool is intended for educational purposes, system administration, and authorized forensic analysis. The author is not responsible for misuse of this tool. Always ensure you have permission before analyzing networks or remote systems.
