# WebStalker

## Introduction
WebStalker is a comprehensive web reconnaissance tool designed for gathering information about websites. It can enumerate subdomains, scan ports, fetch DNS records, gather WHOIS info, detect technologies used, check for sensitive files, and retrieve network CIDR & ASN information.  

> ⚠️ Disclaimer: WebStalker is intended for legal security testing and information gathering on websites you own or have permission to test. Unauthorized scanning of third-party websites may be illegal.  

## Installation
1. Clone the repository:
```bash
git clone https://github.com/sam0x001/webstalker
cd webstalker
```

2. Create a Python virtual environment (optional):
```bash
python -m venv venv
source venv/bin/activate # Linux/macOS
venv\Scripts\activate # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```
- Note: You need scuritytrails API key to use subdomain enumeration feature
## Usage
```bash
python main.py -d example.com [OPTIONS]
```
If no options are provided, all modules will run.

## Options
```
| Short | Long            | Description                             |
|-------|-----------------|-----------------------------------------|
| -d    | --domain        | Target domain (required)                |
| -s    | --subdomain     | Discover subdomains                     |
| -p    | --port          | Port scanning                           | 
| -dn   | --dns-record    | Get DNS records                         |
| -w    | --whois         | Fetch WHOIS information                 |
| -t    | --tech          | Detect technologies used by the site    |
| -sn   | --sensitive     | Scan for sensitive files                |
| -c    | --cidr          | Retrieve CIDR and ASN info              |
| -o    | --output FILE   | Save results to JSON file               |
```

## Example
```bash
python main.py -d example.com -s -p -dn -o output.json
```

**Output:**
```css
[+] Getting Subdomains...
sub1.example.com
sub2.example.com

[+] Scanning Ports...
Open ports: [80, 443, 22]

[+] Fetching DNS Records...
A : 93.184.216.34
MX : mail.example.com
...

[*] Results saved to output.json
```

## Screenshots
<img src="Screenshots/1.jpg" alt="Help message" />
<img src="Screenshots/2.jpg" alt="screenshot" />

## Contact
- GitHub: [github.com/sam0x001](https://github.com/sam0x001)  
- Instagram: [instagram.com/sam0x001](https://instagram.com/sam0x001)
- X (twitter): [x.com/sam00x01](https://x.com/sam00x01)
- Telegram channel: [t.me/cyber0x01](https://t.me/cyber0x01)
- Email: Saminium@duck.com
