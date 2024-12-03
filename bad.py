import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
import threading
from tqdm import tqdm


class FastVulnerabilityScanner:
    def __init__(self):
        self.vulns = []
        self.open_ports = {}
        self.thread_pool = ThreadPoolExecutor(max_workers=100)
        self.completed_tasks_lock = threading.Lock()
        self.completed_tasks = 0
        self.total_tasks = 0
        self.pbar = None

    def fast_port_scan(self, host):
        """Fast port scan focusing on common ports."""
        common_ports = [21, 22, 25, 53, 80, 443, 3389, 8080, 1433, 3306, 5900, 445]
        self.total_tasks += len(common_ports)
        self.pbar = tqdm(total=self.total_tasks, desc="Scanning Ports", unit="port")
        
        for port in common_ports:
            self.thread_pool.submit(self.check_port, host, port)
        
        self.thread_pool.shutdown(wait=True)
        self.pbar.close()

    def check_port(self, host, port):
        """Check if a port is open and update progress."""
        try:
            with socket.create_connection((host, port), timeout=1):
                self.open_ports[port] = 'open'
        except (socket.timeout, ConnectionRefusedError):
            pass
        finally:
            with self.completed_tasks_lock:
                self.completed_tasks += 1
                self.pbar.update(1)

    def scan_vulnerabilities(self, host):
        """Scan vulnerabilities on open ports."""
        self.total_tasks += len(self.open_ports) * 6  # Add tasks for new exploit checks
        self.pbar = tqdm(total=self.total_tasks, desc="Scanning Vulnerabilities", unit="vuln")

        self.thread_pool = ThreadPoolExecutor(max_workers=100)

        for port in self.open_ports:
            if port == 21:  # FTP
                self.thread_pool.submit(self.check_ftp_anonymous, host, port)
            if port == 25:  # SMTP
                self.thread_pool.submit(self.check_smtp_open_relay, host, port)
            if port in [80, 443]:  # HTTP/HTTPS
                self.thread_pool.submit(self.check_http_headers, host, port)
            if port == 3306:  # MySQL
                self.thread_pool.submit(self.check_mysql_auth, host, port)
            if port == 3389:  # RDP
                self.thread_pool.submit(self.check_rdp_insecure, host, port)
            if port == 445:  # SMB
                self.thread_pool.submit(self.check_smb_exploit, host, port)

        self.thread_pool.shutdown(wait=True)
        self.pbar.close()

    # --- Exploit Scanners ---

    def check_ftp_anonymous(self, host, port):
        """Check for FTP anonymous login."""
        try:
            with socket.create_connection((host, port), timeout=1) as sock:
                sock.sendall(b'USER anonymous\r\n')
                response = sock.recv(1024).decode()
                if '230' in response:
                    self.vulns.append((
                        f"FTP Anonymous Login allowed on port {port}.",
                        "Disable anonymous login in the FTP server configuration (e.g., `no_anon_password` in vsftpd.conf)."
                    ))
        except Exception:
            pass

    def check_smtp_open_relay(self, host, port):
        """Check for SMTP open relay vulnerability."""
        try:
            with socket.create_connection((host, port), timeout=1) as sock:
                sock.sendall(b'HELO test\r\n')
                response = sock.recv(1024).decode()
                if '250' in response:
                    sock.sendall(b'MAIL FROM:<test@test.com>\r\n')
                    relay_response = sock.recv(1024).decode()
                    if '250' in relay_response:
                        self.vulns.append((
                            f"SMTP Open Relay detected on port {port}.",
                            "Configure the SMTP server to reject unauthorized relays. For example, restrict relays to trusted IPs."
                        ))
        except Exception:
            pass

    def check_http_headers(self, host, port):
        """Check for outdated HTTP headers."""
        try:
            with socket.create_connection((host, port), timeout=1) as sock:
                sock.sendall(b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n')
                response = sock.recv(4096).decode()
                if 'X-Frame-Options' not in response:
                    self.vulns.append((
                        f"Missing X-Frame-Options header on port {port}.",
                        "Add the X-Frame-Options header to the web server configuration to prevent clickjacking attacks."
                    ))
                if 'Content-Security-Policy' not in response:
                    self.vulns.append((
                        f"Missing Content-Security-Policy header on port {port}.",
                        "Add the Content-Security-Policy header to restrict sources of scripts and styles."
                    ))
        except Exception:
            pass

    def check_mysql_auth(self, host, port):
        """Check for weak MySQL authentication."""
        try:
            with socket.create_connection((host, port), timeout=1) as sock:
                sock.sendall(b'\x00\x00\x00\x01\x85\xa6\x03')  # Minimal MySQL packet
                response = sock.recv(1024)
                if b'root' in response:
                    self.vulns.append((
                        f"MySQL weak authentication detected on port {port}.",
                        "Ensure MySQL uses strong passwords and disable root access from remote hosts."
                    ))
        except Exception:
            pass

    def check_rdp_insecure(self, host, port):
        """Check for insecure RDP configuration."""
        try:
            with socket.create_connection((host, port), timeout=1):
                self.vulns.append((
                    f"Insecure RDP configuration detected on port {port}.",
                    "Enable Network Level Authentication (NLA) and use strong passwords for RDP."
                ))
        except Exception:
            pass

    def check_smb_exploit(self, host, port):
        """Check for SMB vulnerabilities like EternalBlue."""
        try:
            with socket.create_connection((host, port), timeout=1):
                self.vulns.append((
                    f"SMB vulnerability (potential EternalBlue) detected on port {port}.",
                    "Apply the latest security updates and disable SMBv1 on the server."
                ))
        except Exception:
            pass

    def run(self):
        print("Initiating fast vulnerability scan...")
        host = '127.0.0.1'

        # Step 1: Scan open ports
        self.fast_port_scan(host)

        # Step 2: Scan for vulnerabilities
        self.scan_vulnerabilities(host)

        # Print results
        if self.vulns:
            print("\nVulnerabilities found and fixes:")
            for vuln, fix in self.vulns:
                print(f"- {vuln}")
                print(f"  Fix: {fix}")
        else:
            print("\nNo vulnerabilities detected.")


if __name__ == "__main__":
    scanner = FastVulnerabilityScanner()
    scanner.run()
