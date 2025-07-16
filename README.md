# CyberPulse
# 𝙲𝚈𝙱𝙴𝚁𝙿𝚄𝙻𝚂𝙴 | 𝚂𝚎𝚌𝚞𝚛𝚒𝚝𝚢 𝚃𝚎𝚜𝚝𝚒𝚗𝚐 𝙵𝚛𝚊𝚖𝚎𝚠𝚘𝚛𝚔

```
  _____      _               _____      _            
 / ____|    | |             |  __ \    | |           
| |    _   _| |__   ___ _ __| |__) |   | |___  ___   
| |   | | | | '_ \ / _ \ '__|  ___/ | | / __|/ _ \  
| |___| |_| | |_) |  __/ |  | |   | |_| \__ \  __/  
 \_____\__, |_.__/ \___|_|  |_|    \__,_|___/\___|  
        __/ |                                        
       |___/      [WordPress Security Framework v2.0]
```

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

<div align="center">
  <strong>:: ADVANCED WORDPRESS SECURITY SCANNING & TESTING FRAMEWORK ::</strong><br>
  <sub>A CYBERPUNK-THEMED TOOLKIT FOR AUTHORIZED SECURITY TESTING</sub>
</div>

---

## ⟨⟨ SYSTEM OVERVIEW ⟩⟩

CyberPulse is a comprehensive WordPress security testing framework designed for authorized security professionals and penetration testers. With an interactive console interface, rich progress visualization, and advanced scanning capabilities, CyberPulse offers a powerful toolkit for identifying and analyzing vulnerabilities in WordPress installations.

> [!WARNING]
> This framework is for **EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**. Unauthorized use against systems without explicit permission is illegal and unethical. Always obtain proper authorization before conducting security tests.

---

## ⟨⟨ INSTALLATION ⟩⟩

### [01] AUTOMATIC INSTALLATION

Simply run the script and it will automatically detect your operating system and install all required dependencies:

```bash
python3 cyberpulse.py
```

### [02] MANUAL INSTALLATION

If you prefer to install dependencies manually:

#### Debian/Ubuntu:
```bash
apt-get update
apt-get install -y python3-pip python3-requests python3-colorama
pip3 install requests colorama tqdm rich tabulate validators pyfiglet configparser
```

#### CentOS/RHEL/Alma:
```bash
yum update -y
yum install -y python3-pip
pip3 install requests colorama tqdm rich tabulate validators pyfiglet configparser
```

---

## ⟨⟨ QUICKSTART ⟩⟩

### [01] BASIC USAGE

```bash
# Start the interactive interface
python3 cyberpulse.py

# Scan targets from a file
python3 cyberpulse.py -t targets.txt --scan

# Advanced options
python3 cyberpulse.py -t targets.txt --threads 20 --timeout 30 --verbose
```

### [02] COMMAND LINE OPTIONS

| Option | Description |
|--------|-------------|
| `-t, --targets` | Path to file containing target URLs |
| `-o, --output` | Custom output directory for results |
| `-v, --verbose` | Enable verbose output |
| `--threads` | Number of concurrent threads (default: 10) |
| `--timeout` | Request timeout in seconds (default: 15) |
| `--scan` | Start scanning immediately after loading targets |

---

## ⟨⟨ FEATURES ⟩⟩

### [01] CORE CAPABILITIES

- 🔍 **WordPress Detection**: Identify WordPress installations with high accuracy
- 🧩 **Plugin Enumeration**: Discover installed plugins and their versions
- 🚨 **Vulnerability Scanning**: Detect vulnerable Elementor versions (3.5.x and 3.6.0-3.6.2)
- 🔐 **User Registration**: Test for enabled user registration vulnerabilities
- 💉 **Exploitation Framework**: Test for and validate security vulnerabilities
- 📊 **Comprehensive Reporting**: Detailed results in multiple export formats

### [02] UI ENHANCEMENTS

- 🖥️ **Interactive Console**: User-friendly menu-driven interface
- 📈 **Progress Visualization**: Real-time scanning progress with rich display
- 🎨 **Cyberpunk Theming**: Stylish visual elements and color schemes
- 📋 **Structured Output**: Well-organized, easy-to-read results

### [03] TECHNICAL FEATURES

- 🧵 **Multi-threading**: Concurrent scanning for improved performance
- 🔄 **User-Agent Rotation**: Avoid detection with rotating user-agents
- 🧰 **OS Detection**: Cross-platform compatibility with automatic adaptation
- ⚙️ **Configuration Management**: Customizable settings via config file or CLI

---

## ⟨⟨ INTERACTIVE MENU ⟩⟩

CyberPulse features a fully interactive menu system:

1. **Load targets from file** - Import URLs from a text file
2. **Scan targets for WordPress** - Detect WordPress installations
3. **Check for vulnerable Elementor versions** - Identify security vulnerabilities
4. **Advanced WordPress enumeration** - Detailed site analysis
5. **Exploit vulnerable sites** - Test and validate vulnerabilities
6. **Configuration** - Customize tool settings
7. **View results** - Examine and export findings

---

## ⟨⟨ DETAILED TOOLS ⟩⟩

### [01] WORDPRESS SCANNER

The WordPress Scanner module identifies WordPress installations by checking for common files, directories, and signature patterns. It employs multiple detection methods to ensure accuracy even on heavily customized sites.

### [02] ELEMENTOR VULNERABILITY SCANNER

This specialized module detects versions of the Elementor page builder plugin vulnerable to security issues (versions 3.5.x and 3.6.0-3.6.2). It analyzes the plugin's readme.txt file to precisely identify version information.

### [03] PLUGIN ENUMERATOR

The Plugin Enumerator discovers installed WordPress plugins using multiple techniques, including directory analysis and HTML source inspection. This provides valuable insights into the site's potential attack surface.

### [04] EXPLOITATION FRAMEWORK

For authorized testing, this module can validate vulnerabilities by attempting to register users and exploit security weaknesses. All actions are logged for comprehensive reporting.

---

## ⟨⟨ ETHICAL GUIDELINES ⟩⟩

When using CyberPulse, always adhere to these ethical principles:

1. **Obtain Explicit Authorization** - Never test systems without written permission
2. **Respect Scope Limitations** - Stay within authorized boundaries
3. **Minimize Impact** - Avoid actions that could disrupt normal operations
4. **Secure Testing Data** - Protect all information gathered during testing
5. **Responsible Disclosure** - Report findings to the system owner securely
6. **Follow Local Laws** - Comply with all applicable regulations

---

## ⟨⟨ DISCLAIMER ⟩⟩

This tool is provided for educational and authorized security testing purposes only. The creators and contributors assume no liability for misuse or damage caused by improper use of this software. Users are solely responsible for ensuring they have proper authorization before conducting any security tests.

---

## ⟨⟨ LICENSE ⟩⟩

MIT License

Copyright (c) 2025 CyberPulse Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

<div align="center">
  <code>[END OF TRANSMISSION]</code>
</div>
