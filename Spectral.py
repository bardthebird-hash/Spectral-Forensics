from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DirectoryTree, Static, DataTable, TabbedContent, TabPane, Log, Label, Button, Input, ProgressBar, SelectionList, OptionList
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Grid
from textual.binding import Binding
from textual.reactive import reactive
from textual.worker import get_current_worker
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich.syntax import Syntax
import psutil
import os
import hashlib
import datetime
import stat
import threading
import subprocess
import socket
import math
import re
import platform
import glob
import time

# --- Optional Imports for Advanced Features ---
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

# --- Global Case Evidence Storage ---
CASE_EVIDENCE = []

# --- CSS Styling (Cyberpunk Theme) ---
CSS = """
Screen {
    background: #0d1117;
    color: #00ff41;
}

Header {
    background: #161b22;
    color: #00ff41;
    dock: top;
    height: 3;
    content-align: center middle;
    text-style: bold;
    border-bottom: solid #00ff41;
}

Footer {
    background: #161b22;
    color: #00ff41;
    dock: bottom;
    height: 1;
}

/* Tabs */
TabbedContent {
    height: 100%;
    background: #0d1117;
}

ContentSwitcher {
    background: #0d1117;
    height: 1fr;
}

TabPane {
    padding: 1;
    background: #0d1117;
    height: 100%;
}

/* Layout Containers */
#sidebar {
    width: 25%;
    dock: left;
    height: 100%;
    border-right: solid #003300;
    background: #0d1117;
}

#main-content {
    height: 100%;
    width: 100%;
    background: #0d1117;
}

/* Widget Styles */
.info-box {
    border: solid #00ff41;
    background: #0d1117;
    height: auto;
    margin-bottom: 1;
    padding: 1;
}

.data-header {
    text-style: bold;
    color: #ffffff;
    background: #2ea043;
    width: 100%;
    padding-left: 1;
    margin-bottom: 1;
}

DataTable {
    background: #0d1117;
    color: #00ff41;
    border: solid #3fb950;
    height: 100%;
}

DataTable > .datatable--header {
    background: #238636;
    color: white;
    text-style: bold;
}

Button {
    background: #238636;
    color: #ffffff;
    border: none;
    width: 100%;
    margin-top: 1;
}

Button:hover {
    background: #2ea043;
}

Input {
    border: solid #00ff41;
    background: #0d1117;
    color: white;
}

Log {
    border: solid #3fb950;
    background: #0d1117;
    color: #e6edf3;
    height: 100%;
}

ProgressBar {
    tint: #00ff41;
}

OptionList {
    background: #0d1117;
    border: solid #00ff41;
}
"""

# --- Helper Classes ---

class SystemMonitor(Static):
    """Displays live system stats."""
    cpu_usage = reactive(0.0)
    ram_usage = reactive(0.0)

    def on_mount(self) -> None:
        self.update_timer = self.set_interval(2.0, self.update_stats)

    def update_stats(self) -> None:
        self.cpu_usage = psutil.cpu_percent()
        self.ram_usage = psutil.virtual_memory().percent
        self.update(f"[bold]SYSTEM VITALS[/bold]\nCPU: {self.cpu_usage}%\nRAM: {self.ram_usage}%")

class PDFReportGenerator:
    """Generates a PDF report from collected evidence."""
    def generate(self, filename="forensic_report.pdf"):
        if not HAS_FPDF:
            return False, "FPDF library not installed."
        
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Courier", size=12)
            
            # Header
            pdf.set_font("Courier", style="B", size=16)
            pdf.cell(200, 10, txt="SPECTRAL FORENSICS REPORT", ln=1, align='C')
            pdf.set_font("Courier", size=10)
            pdf.cell(200, 10, txt=f"Generated: {datetime.datetime.now()}", ln=1, align='C')
            pdf.ln(10)
            
            # Evidence
            pdf.set_font("Courier", size=10)
            for item in CASE_EVIDENCE:
                pdf.set_text_color(0, 0, 0)
                if item['type'] == 'header':
                    pdf.set_font("Courier", style="B", size=12)
                    pdf.cell(0, 10, f"[{item['timestamp']}] {item['data']}", ln=1)
                else:
                    pdf.set_font("Courier", size=10)
                    clean_data = str(item['data']).encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 5, f"Type: {item['type']}\nDesc: {item['desc']}\nData: {clean_data}\n" + "-"*50)
                pdf.ln(2)
                
            pdf.output(filename)
            return True, f"Report saved to {filename}"
        except Exception as e:
            return False, str(e)

# --- Feature Widgets ---

class ProcessView(Static):
    """Live Process Monitor."""
    def compose(self) -> ComposeResult:
        yield Label("LIVE PROCESS TABLE", classes="data-header")
        yield Button("Refresh Processes", id="btn-refresh-proc")
        yield DataTable(id="proc-table")

    def on_mount(self):
        table = self.query_one("#proc-table", DataTable)
        table.add_columns("PID", "Name", "User", "Status", "Memory %")
        self.refresh_processes()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-refresh-proc":
            self.refresh_processes()

    def refresh_processes(self):
        table = self.query_one("#proc-table", DataTable)
        table.clear()
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'status', 'memory_percent']):
            try:
                procs.append(p.info)
            except:
                pass
        
        procs.sort(key=lambda x: x['memory_percent'] or 0, reverse=True)
        
        for p in procs[:50]:
            mem = f"{p['memory_percent']:.2f}" if p['memory_percent'] else "0.00"
            table.add_row(
                str(p['pid']), 
                p['name'], 
                p['username'] or "N/A", 
                p['status'], 
                mem
            )

class NetworkView(Static):
    """Live Network Monitor."""
    def compose(self) -> ComposeResult:
        yield Label("ACTIVE CONNECTIONS", classes="data-header")
        yield Button("Refresh Connections", id="btn-refresh-net")
        yield DataTable(id="net-table")

    def on_mount(self):
        table = self.query_one("#net-table", DataTable)
        table.add_columns("Proto", "Local Address", "Remote Address", "Status", "PID")
        self.refresh_network()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-refresh-net":
            self.refresh_network()

    def refresh_network(self):
        table = self.query_one("#net-table", DataTable)
        table.clear()
        try:
            connections = psutil.net_connections()
            for c in connections:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                table.add_row(
                    proto,
                    laddr,
                    raddr,
                    c.status,
                    str(c.pid)
                )
        except Exception as e:
            table.add_row("ERR", "Access Denied", "Run as Root", str(e), "-")

class RemoteUplink(Static):
    """SSH Client."""
    def compose(self) -> ComposeResult:
        yield Label("REMOTE UPLINK (SSH)", classes="data-header")
        with Grid(id="ssh-grid"):
            yield Input(placeholder="Hostname/IP", id="ssh-host")
            yield Input(placeholder="Username", id="ssh-user")
            yield Input(placeholder="Password", id="ssh-pass", password=True)
            yield Input(placeholder="Command", id="ssh-cmd")
            yield Button("Execute Command", id="btn-ssh-exec")
        yield Log(id="ssh-log")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-ssh-exec":
            self.run_ssh()

    def run_ssh(self):
        log = self.query_one("#ssh-log", Log)
        if not HAS_PARAMIKO:
            log.write("[red]ERROR: 'paramiko' library not found. Install it to use SSH.[/red]")
            return

        host = self.query_one("#ssh-host", Input).value
        user = self.query_one("#ssh-user", Input).value
        password = self.query_one("#ssh-pass", Input).value
        cmd = self.query_one("#ssh-cmd", Input).value

        log.write(f"[yellow]Connecting to {host}...[/yellow]")
        
        def _ssh_task():
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, username=user, password=password, timeout=5)
                
                stdin, stdout, stderr = client.exec_command(cmd)
                output = stdout.read().decode()
                error = stderr.read().decode()
                
                if output:
                    self.app.call_from_thread(log.write, f"[green]OUTPUT:[/green]\n{output}")
                if error:
                    self.app.call_from_thread(log.write, f"[red]ERROR:[/red]\n{error}")
                
                client.close()
                self.app.call_from_thread(log.write, "[blue]Connection Closed.[/blue]")
            except Exception as e:
                self.app.call_from_thread(log.write, f"[red]Connection Failed: {e}[/red]")

        threading.Thread(target=_ssh_task, daemon=True).start()

class EntropyAnalyzer(Static):
    """Calculates Shannon Entropy."""
    
    def compose(self) -> ComposeResult:
        yield Label("ENTROPY ANALYSIS (Encryption Detector)", classes="data-header")
        yield Label("0.0 = Organized | 8.0 = Random/Encrypted", id="entropy-scale")
        yield ProgressBar(total=8.0, show_eta=False, id="entropy-bar")
        yield Static(id="entropy-val")
        yield Button("Run Analysis", id="btn-run-entropy")

    def run_analysis(self, file_path):
        if not file_path: return
        self.query_one("#entropy-val", Static).update("[yellow]Calculating...[/yellow]")
        
        def _calc():
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(1024 * 1024) 
                
                if not data:
                    entropy = 0
                else:
                    entropy = 0
                    for x in range(256):
                        p_x = float(data.count(x)) / len(data)
                        if p_x > 0:
                            entropy += - p_x * math.log(p_x, 2)
                
                self.app.call_from_thread(self.update_ui, entropy)
            except Exception as e:
                 self.app.call_from_thread(self.query_one("#entropy-val", Static).update, f"Error: {e}")

        threading.Thread(target=_calc, daemon=True).start()

    def update_ui(self, entropy):
        bar = self.query_one("#entropy-bar", ProgressBar)
        bar.update(progress=entropy)
        
        color = "green"
        verdict = "Text/Code"
        if entropy > 5.0: 
            color = "yellow"
            verdict = "Unknown/Mixed"
        if entropy > 7.0: 
            color = "red"
            verdict = "Encrypted/Packed"

        self.query_one("#entropy-val", Static).update(f"[{color}]Entropy: {entropy:.4f} ({verdict})[/{color}]")

class PatternHunter(Static):
    """Scans for IPs, Emails, and URLs."""
    
    def compose(self) -> ComposeResult:
        yield Label("IOC PATTERN HUNTER", classes="data-header")
        yield SelectionList(
            ("IPv4 Addresses", "ipv4"),
            ("Email Addresses", "email"),
            ("URLs", "url"),
            ("MAC Addresses", "mac"),
            id="pattern-select"
        )
        yield Button("Scan File", id="btn-scan-patterns")
        yield Log(id="scan-results")

    def scan_file(self, file_path):
        if not file_path: return
        
        selected = self.query_one("#pattern-select", SelectionList).selected
        log = self.query_one("#scan-results", Log)
        log.clear()
        
        patterns = {
            "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
            "mac": r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
        }
        
        log.write(f"[yellow]Scanning {os.path.basename(file_path)}...[/yellow]")
        
        def _scan():
            found_count = 0
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read(1024 * 1024 * 5) # 5MB limit
                
                for p_key in selected:
                    regex = patterns[p_key]
                    matches = re.findall(regex, content)
                    if matches:
                        log.write(f"\n[bold cyan]--- Found {len(matches)} {p_key.upper()}s ---[/bold cyan]")
                        # Show unique only
                        for m in set(matches):
                            log.write(str(m))
                            found_count += 1
                    else:
                        log.write(f"\nNo {p_key} found.")
                        
                if found_count == 0:
                    log.write("\n[green]Clean scan. No patterns matched.[/green]")
                    
            except Exception as e:
                log.write(f"[red]Error reading file: {e}[/red]")

        threading.Thread(target=_scan, daemon=True).start()

# --- POWER MODULES (New in v4.0) ---

class TimelineAnalyzer(Static):
    """Reconstructs file activity timelines recursively."""
    
    def compose(self) -> ComposeResult:
        yield Label("TIMELINE RECONSTRUCTION", classes="data-header")
        yield Input(placeholder="Path to scan (e.g. /var/log or /home)", id="timeline-path")
        yield Button("Build Timeline", id="btn-build-timeline")
        yield DataTable(id="timeline-table")

    def on_mount(self):
        table = self.query_one("#timeline-table", DataTable)
        table.add_columns("Timestamp", "Action", "File Path")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-build-timeline":
            path = self.query_one("#timeline-path", Input).value
            if not path or not os.path.exists(path):
                self.app.notify("Invalid path", severity="error")
                return
            self.build_timeline(path)

    def build_timeline(self, start_path):
        table = self.query_one("#timeline-table", DataTable)
        table.clear()
        self.app.notify(f"Scanning {start_path}...", title="Timeline Started")

        def _scan():
            events = []
            # Limit scan depth/count for TUI performance
            count = 0
            max_files = 1000
            
            for root, dirs, files in os.walk(start_path):
                for name in files:
                    if count >= max_files: break
                    try:
                        filepath = os.path.join(root, name)
                        stats = os.stat(filepath)
                        # Add Modified Time
                        events.append((stats.st_mtime, "MODIFIED", filepath))
                        # Add Change Time
                        events.append((stats.st_ctime, "CHANGED", filepath))
                        count += 1
                    except:
                        pass
                if count >= max_files: break
            
            # Sort by timestamp descending (newest first)
            events.sort(key=lambda x: x[0], reverse=True)
            
            def _update_ui():
                for ts, action, fp in events:
                    dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                    table.add_row(dt, action, fp)
                self.app.notify(f"Processed {len(events)} events", title="Timeline Complete")

            self.app.call_from_thread(_update_ui)

        threading.Thread(target=_scan, daemon=True).start()

class PersistenceHunter(Static):
    """Checks for auto-starting malware/scripts."""
    
    def compose(self) -> ComposeResult:
        yield Label("PERSISTENCE HUNTER", classes="data-header")
        yield Button("Scan Auto-Start Locations", id="btn-scan-persist")
        yield Log(id="persist-log")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-scan-persist":
            self.scan_persistence()

    def scan_persistence(self):
        log = self.query_one("#persist-log", Log)
        log.clear()
        
        locations = [
            "/etc/crontab",
            "/etc/rc.local",
            "/etc/passwd", # Check for weird users
        ]
        # Dirs to list
        dirs = [
            "/etc/cron.d/",
            "/etc/cron.daily/",
            "/etc/cron.hourly/",
            "/var/spool/cron/crontabs/",
            "/etc/systemd/system/",
            "/etc/init.d/"
        ]

        def _hunt():
            self.app.call_from_thread(log.write, "[yellow]Scanning Cron & Init Systems...[/yellow]")
            
            # Check Files
            for loc in locations:
                if os.path.exists(loc):
                    self.app.call_from_thread(log.write, f"\n[bold green]Found {loc}:[/bold green]")
                    try:
                        with open(loc, 'r') as f:
                            # Read first few lines
                            head = f.readlines()[:5]
                            for line in head:
                                if line.strip() and not line.startswith("#"):
                                    self.app.call_from_thread(log.write, f"  {line.strip()}")
                    except:
                        self.app.call_from_thread(log.write, "  [red]Access Denied[/red]")

            # Check Directories
            for d in dirs:
                if os.path.exists(d):
                    self.app.call_from_thread(log.write, f"\n[bold green]Listing {d}:[/bold green]")
                    try:
                        files = os.listdir(d)
                        for f in files[:10]: # Limit output
                             self.app.call_from_thread(log.write, f"  [cyan]{f}[/cyan]")
                        if len(files) > 10:
                            self.app.call_from_thread(log.write, f"  ... and {len(files)-10} more")
                    except:
                        self.app.call_from_thread(log.write, "  [red]Access Denied[/red]")

        threading.Thread(target=_hunt, daemon=True).start()

class LogSentinel(Static):
    """Advanced Log Viewer with Keyword Highlighting."""
    
    def compose(self) -> ComposeResult:
        yield Label("LOG SENTINEL", classes="data-header")
        yield Horizontal(
            Button("Syslog", id="btn-log-sys", classes="btn-small"),
            Button("Auth Log", id="btn-log-auth", classes="btn-small"),
            Button("Dmesg", id="btn-log-dmesg", classes="btn-small"),
            classes="btn-row"
        )
        yield Log(id="log-viewer")

    def on_button_pressed(self, event: Button.Pressed):
        log_view = self.query_one("#log-viewer", Log)
        log_view.clear()
        
        target = ""
        if event.button.id == "btn-log-sys": target = "/var/log/syslog"
        elif event.button.id == "btn-log-auth": target = "/var/log/auth.log"
        elif event.button.id == "btn-log-dmesg": target = "dmesg"

        self.read_log(target)

    def read_log(self, target):
        log_view = self.query_one("#log-viewer", Log)
        
        def _read():
            lines = []
            try:
                if target == "dmesg":
                    # Run dmesg command
                    res = subprocess.run(["dmesg"], capture_output=True, text=True)
                    lines = res.stdout.splitlines()[-100:] # Last 100 lines
                elif os.path.exists(target):
                    # Tail file
                    with open(target, 'r', errors='ignore') as f:
                        # diverse way to get last lines efficiently would be seek, but simple readlines is ok for now
                        lines = f.readlines()[-100:]
                else:
                    self.app.call_from_thread(log_view.write, f"[red]Log file {target} not found or accessible.[/red]")
                    return

                for line in lines:
                    line = line.strip()
                    if not line: continue
                    
                    # Syntax Highlighting
                    style = "white"
                    if "error" in line.lower() or "failed" in line.lower():
                        style = "bold red"
                    elif "sudo" in line.lower() or "root" in line.lower():
                        style = "bold yellow"
                    elif "accepted" in line.lower() or "session opened" in line.lower():
                        style = "green"
                    
                    self.app.call_from_thread(log_view.write, Text(line, style=style))
            
            except Exception as e:
                self.app.call_from_thread(log_view.write, f"[red]Error reading log: {e}[/red]")

        threading.Thread(target=_read, daemon=True).start()

class SystemRecon(Static):
    """Detailed System Information."""
    def compose(self) -> ComposeResult:
        yield Label("DEEP SYSTEM RECON", classes="data-header")
        yield Static(id="recon-data")

    def on_mount(self):
        self.refresh_data()
        
    def refresh_data(self):
        uname = platform.uname()
        try:
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except:
            boot_time = "Unknown"
        
        info = f"""
        [bold green]Node:[/bold green] {uname.node}
        [bold green]OS:[/bold green]   {uname.system} {uname.release}
        [bold green]Kernel:[/bold green] {uname.version}
        [bold green]Arch:[/bold green]   {uname.machine}
        [bold green]CPU:[/bold green]    {psutil.cpu_count(logical=True)} Threads / {psutil.cpu_count(logical=False)} Cores
        [bold green]Boot:[/bold green]   {boot_time}
        [bold green]Python:[/bold green] {platform.python_version()}
        """
        self.query_one("#recon-data", Static).update(info)

class FileInspector(Static):
    """Detailed view for a selected file."""
    current_file = reactive(None)

    def compose(self) -> ComposeResult:
        with TabbedContent(initial="metadata"):
            with TabPane("Metadata", id="metadata"):
                with VerticalScroll(id="meta-container"):
                    yield Static(id="meta-view", expand=True)
                yield Button("Add Metadata to Case", id="btn-case-meta")
            with TabPane("Hex/Magic", id="hexdump"):
                yield Label("Magic Bytes Header Check", classes="data-header")
                yield Static(id="magic-view")
                yield Label("Hex Dump (First 512B)", classes="data-header")
                yield Static(id="hex-view", expand=True)
            with TabPane("Entropy", id="entropy"):
                yield EntropyAnalyzer(id="entropy-analyzer")
            with TabPane("Pattern Hunter", id="hunter"):
                yield PatternHunter(id="pattern-hunter")
            with TabPane("Hashing", id="hashing"):
                yield Button("Calculate Hashes", id="btn-hash")
                yield Static(id="hash-result")
                yield Button("Add Hash to Case", id="btn-case-hash")

    def watch_current_file(self, file_path):
        if not file_path: return
        self.query_one("#hash-result", Static).update("Press button to calculate.")
        try:
            stat_info = os.stat(file_path)
            mode = stat.filemode(stat_info.st_mode)
            meta_text = f"""
            [bold green]File:[/bold green] {file_path}
            [bold green]Size:[/bold green] {stat_info.st_size} bytes
            [bold green]Permissions:[/bold green] {mode}
            [bold green]Modified:[/bold green] {datetime.datetime.fromtimestamp(stat_info.st_mtime)}
            """
            self.query_one("#meta-view", Static).update(meta_text)
            self.update_hex_view(file_path)
        except Exception as e:
            self.query_one("#meta-view", Static).update(f"[red]Error: {e}[/red]")

    def update_hex_view(self, file_path):
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                f.seek(0)
                chunk = f.read(512)
            
            # Magic Byte Check
            hex_header = header.hex().upper()
            magic_text = f"[bold white]Header Bytes:[/bold white] {hex_header}\n"
            
            # Simple common signatures
            sigs = {
                "FFD8FF": "JPEG Image",
                "89504E47": "PNG Image",
                "25504446": "PDF Document",
                "4D5A": "Windows PE Executable (EXE/DLL)",
                "7F454C46": "Linux ELF Executable",
                "504B0304": "ZIP Archive"
            }
            
            detected = "Unknown"
            for sig, desc in sigs.items():
                if hex_header.startswith(sig):
                    detected = desc
                    break
            
            if detected == "Unknown":
                magic_text += f"[yellow]Signature:[/yellow] Unknown Binary format"
            else:
                magic_text += f"[bold green]Signature Detected:[/bold green] {detected}"
                
            self.query_one("#magic-view", Static).update(magic_text)

            # Hex Dump
            hex_output = Text()
            for i in range(0, len(chunk), 16):
                line_chunk = chunk[i:i+16]
                hex_output.append(f"{i:08x}  ", style="bold cyan")
                hex_values = " ".join(f"{b:02x}" for b in line_chunk)
                hex_output.append(f"{hex_values:<48}  ", style="green")
                ascii_repr = "".join((chr(b) if 32 <= b < 127 else ".") for b in line_chunk)
                hex_output.append(f"{ascii_repr}\n", style="white")
            self.query_one("#hex-view", Static).update(hex_output)
        except Exception as e:
            self.query_one("#magic-view", Static).update(f"Error: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-hash":
            self.calculate_hashes()
        elif event.button.id == "btn-case-meta":
            self.add_to_case("Metadata", f"Analysis of {self.current_file}")
        elif event.button.id == "btn-case-hash":
            hash_data = self.query_one("#hash-result", Static).renderable
            self.add_to_case("Hash Analysis", str(hash_data))
        elif event.button.id == "btn-run-entropy":
            self.query_one("#entropy-analyzer", EntropyAnalyzer).run_analysis(self.current_file)
        elif event.button.id == "btn-scan-patterns":
            self.query_one("#pattern-hunter", PatternHunter).scan_file(self.current_file)

    def calculate_hashes(self):
        file_path = self.current_file
        if not file_path: return
        
        result_widget = self.query_one("#hash-result", Static)
        result_widget.update("[yellow]Calculating...[/yellow]")

        def run_hash():
            try:
                md5 = hashlib.md5()
                sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        md5.update(chunk)
                        sha256.update(chunk)
                output = f"MD5: {md5.hexdigest()}\nSHA256: {sha256.hexdigest()}"
                self.app.call_from_thread(result_widget.update, output)
            except Exception as e:
                self.app.call_from_thread(result_widget.update, str(e))

        threading.Thread(target=run_hash, daemon=True).start()

    def add_to_case(self, evidence_type, data):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        CASE_EVIDENCE.append({
            "type": evidence_type,
            "timestamp": timestamp,
            "desc": f"Evidence from Inspector",
            "data": data
        })
        self.app.notify(f"Added {evidence_type} to Case File")

class CaseReportView(Static):
    """View and export case evidence."""
    def compose(self) -> ComposeResult:
        yield Label("CASE EVIDENCE LOCKER", classes="data-header")
        yield Button("Generate PDF Report", id="btn-pdf")
        yield Log(id="case-log")

    def on_mount(self):
        self.log_view = self.query_one("#case-log", Log)
        self.update_log()

    def update_log(self):
        self.log_view.clear()
        if not CASE_EVIDENCE:
            self.log_view.write("No evidence collected yet.")
            return
        for item in CASE_EVIDENCE:
            self.log_view.write(f"[{item['timestamp']}] {item['type']}: {item['desc']}")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-pdf":
            gen = PDFReportGenerator()
            success, msg = gen.generate()
            if success:
                self.app.notify(msg)
            else:
                self.app.notify(f"Error: {msg}", severity="error")

class SpectralForensicsApp(App):
    """The Main Application Class."""
    CSS = CSS
    BINDINGS = [("q", "quit", "Quit"), ("d", "toggle_dark", "Dark Mode")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="app-grid"):
            with Vertical(id="sidebar"):
                yield Label("SYSTEM TARGET", classes="data-header")
                yield SystemMonitor(classes="info-box")
                yield Label("NAVIGATOR", classes="data-header")
                # START AT ROOT DIRECTORY FOR FULL SYSTEM ACCESS
                yield DirectoryTree("/", id="tree-view")
            
            with Vertical(id="main-content"):
                with TabbedContent(initial="tab-files"):
                    with TabPane("File System", id="tab-files"):
                        yield FileInspector(id="inspector")
                    with TabPane("Live Processes", id="tab-procs"):
                        yield ProcessView()
                    with TabPane("Network", id="tab-net"):
                        yield NetworkView()
                    with TabPane("Remote Uplink", id="tab-ssh"):
                        yield RemoteUplink()
                    with TabPane("Timeline", id="tab-timeline"):
                        yield TimelineAnalyzer()
                    with TabPane("Persistence", id="tab-persist"):
                        yield PersistenceHunter()
                    with TabPane("Log Sentinel", id="tab-logs"):
                        yield LogSentinel()
                    with TabPane("Deep Recon", id="tab-recon"):
                        yield SystemRecon()
                    with TabPane("Case Report", id="tab-report"):
                        yield CaseReportView(id="report-view")

        yield Footer()

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        # User notification to confirm click registered
        self.notify(f"Analyzing: {event.path.name}", title="File Selected")
        
        inspector = self.query_one("#inspector", FileInspector)
        inspector.current_file = event.path.as_posix()
        # Also auto-fill Timeline path for convenience
        timeline = self.query_one("#timeline-path", Input)
        if timeline:
            timeline.value = os.path.dirname(event.path.as_posix())

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated):
        # Refresh the report view when clicking the tab
        if event.tab.id == "tab-report":
            self.query_one("#report-view", CaseReportView).update_log()

    def on_mount(self) -> None:
        self.title = "SPECTRAL // FORENSICS // v4.0 (POWER)"

if __name__ == "__main__":
    app = SpectralForensicsApp()
    app.run()
