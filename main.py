import requests, socket, json, argparse, dns.resolver
from builtwith import builtwith
from ipwhois import IPWhois

def banner():
    print(r"""
 _       __     __   _____ __        ____
| |     / /__  / /_ / ___// /_____ _/ / /_____  _____
| | /| / / _ \/ __ \\__ \/ __/ __ `/ / //_/ _ \/ ___/
| |/ |/ /  __/ /_/ /__/ / /_/ /_/ / / ,< /  __/ /
|__/|__/\___/_.___/____/\__/\__,_/_/_/|_|\___/_/
                        by: github.com/sam0x001
          """)


# Subdomain Enumeration
def subdomain(target):
    ## Enter your securitytrails API key here
    SECURITYTRAILS_API_KEY = ""
    
    if not SECURITYTRAILS_API_KEY:
        return "[!] NO_API_KEY"
    
    url = f'https://api.securitytrails.com/v1/domain/{target}/subdomains'
    headers = {'APIKEY': SECURITYTRAILS_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        st_subdomains = response.json().get('subdomains', [])

        if not st_subdomains:
            return "[!] No subdomains found"

        return "\n".join(f"{sub}.{target}" for sub in st_subdomains)
    
    except requests.exceptions.HTTPError as http_error:
        return f"[!] HTTP Error: {http_error}"
    
    except requests.exceptions.RequestException as req_error:
        return f"[!] Request Error: {req_error}"
    
    except Exception as error:
        return f"[!!] Error: {error}"

# Port scanning
def port(target):
    common_ports = [
    80, 443, 8080, 8443,
    25, 465, 587, 110, 995, 143, 993,
    3306, 5432, 1433, 1521, 27017,
    22, 21, 23, 3389, 5900,
    137, 138, 139, 445, 389, 636, 161, 162, 69, 500, 5060, 5061 ]

    open_ports = []
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port) 
        except Exception:
            pass
        finally:
            sock.close()
            
    return f"Open Ports: {open_ports}"

# DNS Records
def dns_records(target):
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA']
    results = []
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            values = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            values = []
        except dns.resolver.Timeout:
            values = ["Timeout"]
        except Exception:
            values = ["Error"]
        
        results.append(f"{rtype:<5}: {', '.join(values) if values else 'Not found'}")

    return results

# Whois info
def whois(target):
    if target.endswith(("com", "org", "net")):
        srv = "whois.internic.net"
    else:
        srv = "whois.iana.org"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((srv, 43))
        sock.send((target + "\r\n").encode())
        response = sock.recv(10000).decode()
        return response
    except socket.error as error:
        return f"[!] Socket Error: {error}"
    except Exception as error:
        return f"[!!] Error: {error}"
    finally:
        sock.close()
    
# Detecting Technologies
def tech(target):
    try:
        tech_info = builtwith(f"http://{target}")
        if not tech_info:
            return "[!] No technology information found"

        formatted = []
        for key, values in tech_info.items():
            formatted.append(f"{key.replace('-', ' ').title()}: {', '.join(values)}")

        return "\n".join(formatted)

    except Exception as e:
        return f"[!!] Error: {e}"

# Scanning sensitive files
def sensitive_info(target):
    keywords = [".env","config.php","config.json","wp-config.php","settings.php","database.yml",
                "config.inc.php","credentials.json","backup.zip","backup.tar.gz","backup.sql",
                "old.zip","old.tar.gz","old.sql","site.bak","index.php.bak","config.php.bak",
                ".htaccess",".htpasswd","robots.txt","sitemap.xml","README.md","LICENSE",
                "changelog.txt","phpinfo.php","wp-admin/install.php","wp-login.php","administrator/index.php",
                "user/login","admin/config.php","debug.log","error_log",".git/config",
                ".gitignore",".svn/entries",".DS_Store",".git/HEAD"]
    
    found = []

    for keyword in keywords:
        url = f"http://{target}/{keyword}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                found.append(f"{url}")
        except requests.exceptions.RequestException:
            continue
    
    if not found:
        return "[!] No sensitive information found"
    
    return "\n".join(found)

# Get CIDR and ASN info
def cidr_asn(target):
    try:
        ip_address = socket.gethostbyname(target)

        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()

        cidr = result.get('network', {}).get('cidr', 'CIDR not found')
        asn = result.get('asn', 'ASN not found')
        asn_org = result.get('asn_description', 'ASN description not found')

        return f"{target} : ({ip_address})\nCIDR: {cidr}\nASN: {asn}\nASN Org: {asn_org}"

    except socket.gaierror:
        return "[!] Unable to resolve domain"
    except Exception as e:
        return f"[!!] Error: {e}"


def main():
    parser = argparse.ArgumentParser(description="WebStalker Recon Tool")
    parser.add_argument("-d","--domain", help="Target domain")
    parser.add_argument("-s","--subdomain", action="store_true", help="Discover subdomains")
    parser.add_argument("-p","--port", action="store_true", help="Port scanning")
    parser.add_argument("-dn","--dns-record", action="store_true", help="Get DNS records")
    parser.add_argument("-w","--whois", action="store_true", help="Whois info")
    parser.add_argument("-t","--tech", action="store_true", help="Technology info")
    parser.add_argument("-sn","--sensitive", action="store_true", help="Sensitive files")
    parser.add_argument("-c","--cidr", action="store_true", help="CIDR and ASN")
    parser.add_argument("-o","--output", help="Output JSON file")
    args = parser.parse_args()

    if not args.domain:
        print("Use -h/--help for more information.")
        return

    banner()
    target = args.domain
    do_all = not any([args.subdomain, args.port, args.dns_record, args.whois, args.tech, args.sensitive, args.cidr])

    result = {}

    if args.subdomain or do_all:
        print("\n[+] Getting Subdomains...")
        subs = subdomain(target)
        result['subdomains'] = subs
        print(subs)

    if args.port or do_all:
        print("\n[+] Scanning Ports...")
        ports = port(target)
        result['open_ports'] = ports
        print(ports)

    if args.dns_record or do_all:
        print("\n[+] Fetching DNS Records...")
        dns_info = dns_records(target)
        result['dns'] = dns_info
        for record in dns_info:
            print(record)


    if args.whois or do_all:
        print("\n[+] Fetching Whois Info...")
        whois_info = whois(target)
        result['whois'] = whois_info
        print(whois_info)    

    if args.tech or do_all:
        print("\n[+] Detecting Technologies...")
        tech_info = tech(target)
        result['technology'] = tech_info
        print(tech_info)
    
    if args.sensitive or do_all:
        print("\n[+] Searching for Sensitive Files...")
        sens = sensitive_info(target)
        result['sensitive_files'] = sens
        print(sens)

    if args.cidr or do_all:
        print("\n[+] Fetching CIDR and ASN Info...")
        cidr_info = cidr_asn(target)
        result['cidr_asn'] = cidr_info
        print(cidr_info)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=8)
        print(f"\n[*] Results saved to {args.output}")

if __name__ == "__main__":
    main()