
"""
KitFind Python Analysis Module
Supplementary analysis engine for advanced reconnaissance.
For authorized security assessment use only.

Usage:
    python3 analyzer.py <target> [--module dns|ssl|headers|tech]
    python3 analyzer.py example.com --module all
"""

import sys
import json
import socket
import ssl
import http.client
import urllib.parse
import argparse
from datetime import datetime, timezone
from typing import Optional



def analyze_dns(target: str) -> dict:
    """Perform supplementary DNS analysis."""
    try:
        import dns.resolver
        import dns.reversename
    except ImportError:
        return {"error": "dnspython not installed. Run: pip install dnspython"}

    results = {
        "domain": target,
        "records": {},
        "email_security": {}
    }

    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    for rtype in rtypes:
        try:
            answers = resolver.resolve(target, rtype)
            results["records"][rtype] = [str(r) for r in answers]
        except Exception:
            pass


    try:
        dmarc = resolver.resolve(f"_dmarc.{target}", "TXT")
        results["email_security"]["dmarc"] = str(dmarc[0])
    except Exception:
        results["email_security"]["dmarc"] = None

    for txt in results["records"].get("TXT", []):
        if txt.startswith("v=spf1"):
            results["email_security"]["spf"] = txt

    return results




def analyze_ssl(target: str, port: int = 443) -> dict:
    """Perform supplementary SSL/TLS analysis."""
    results = {
        "host": target,
        "port": port,
        "cipher": None,
        "protocol": None,
        "cert": {},
        "issues": []
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cipher = ssock.cipher()
                results["cipher"] = cipher[0] if cipher else None
                results["protocol"] = ssock.version()

                cert = ssock.getpeercert()
                if cert:
                    results["cert"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "sans": [v for _, v in cert.get("subjectAltName", [])]
                    }


                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        not_after = not_after.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (not_after - now).days
                        results["cert"]["days_until_expiry"] = days_left
                        if days_left < 0:
                            results["issues"].append("CRITICAL: Certificate is expired")
                        elif days_left < 30:
                            results["issues"].append(f"WARNING: Certificate expires in {days_left} days")

    except ssl.SSLError as e:
        results["issues"].append(f"SSL Error: {e}")
    except Exception as e:
        results["error"] = str(e)

    return results




def analyze_headers(target: str) -> dict:
    """Analyze HTTP security headers."""
    parsed = urllib.parse.urlparse(target if target.startswith("http") else f"https://{target}")
    host = parsed.netloc or parsed.path
    path = parsed.path or "/"

    results = {
        "url": f"https://{host}{path}",
        "headers": {},
        "checks": [],
        "score": 0
    }

    security_headers = {
        "Strict-Transport-Security": {
            "required": True,
            "description": "HSTS prevents SSL stripping attacks"
        },
        "Content-Security-Policy": {
            "required": True,
            "description": "CSP prevents XSS attacks"
        },
        "X-Frame-Options": {
            "required": True,
            "description": "Prevents clickjacking"
        },
        "X-Content-Type-Options": {
            "required": True,
            "description": "Prevents MIME sniffing"
        },
        "Referrer-Policy": {
            "required": False,
            "description": "Controls referrer information"
        },
        "Permissions-Policy": {
            "required": False,
            "description": "Controls browser feature permissions"
        }
    }

    try:
        conn = http.client.HTTPSConnection(host, timeout=10)
        conn.request("HEAD", path, headers={"User-Agent": "KitFind/1.0"})
        resp = conn.getresponse()

        for key, val in resp.getheaders():
            results["headers"][key.lower()] = val

        score = 0
        for header, info in security_headers.items():
            present = header.lower() in {k.lower(): v for k, v in results["headers"].items()}
            check = {
                "header": header,
                "present": present,
                "required": info["required"],
                "description": info["description"]
            }
            if present:
                score += 20 if info["required"] else 10
            results["checks"].append(check)

        results["score"] = min(score, 100)

    except Exception as e:
        results["error"] = str(e)

    return results




def analyze_tech(target: str) -> dict:
    """Supplementary technology detection."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        return {"error": "Install: pip install requests beautifulsoup4"}

    url = target if target.startswith("http") else f"https://{target}"
    results = {"url": url, "technologies": [], "meta": {}}

    try:
        resp = requests.get(url, timeout=10,
                            headers={"User-Agent": "KitFind/1.0"},
                            allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")


        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property", "")
            content = meta.get("content", "")
            if name and content:
                results["meta"][name] = content


        gen = results["meta"].get("generator", "")
        if gen:
            results["technologies"].append({
                "name": gen,
                "category": "CMS/Generator",
                "source": "meta[generator]",
                "confidence": 90
            })


        scripts = [s.get("src", "") for s in soup.find_all("script", src=True)]
        for script in scripts:
            if "jquery" in script.lower():
                results["technologies"].append({"name": "jQuery", "category": "JS Library", "source": "script", "confidence": 90})
            if "react" in script.lower():
                results["technologies"].append({"name": "React", "category": "JS Framework", "source": "script", "confidence": 85})
            if "vue" in script.lower():
                results["technologies"].append({"name": "Vue.js", "category": "JS Framework", "source": "script", "confidence": 85})

    except Exception as e:
        results["error"] = str(e)

    return results




def calculate_risk(dns_res: dict, ssl_res: dict, headers_res: dict) -> dict:
    """Calculate aggregated risk score."""
    risk = 0
    issues = []


    for issue in ssl_res.get("issues", []):
        if "CRITICAL" in issue:
            risk += 30
            issues.append({"severity": "critical", "message": issue})
        elif "WARNING" in issue:
            risk += 10
            issues.append({"severity": "high", "message": issue})


    for check in headers_res.get("checks", []):
        if not check["present"] and check["required"]:
            risk += 8
            issues.append({
                "severity": "medium",
                "message": f"Missing security header: {check['header']}"
            })


    email_sec = dns_res.get("email_security", {})
    if not email_sec.get("spf"):
        risk += 5
        issues.append({"severity": "low", "message": "No SPF record - email spoofing risk"})
    if not email_sec.get("dmarc"):
        risk += 5
        issues.append({"severity": "low", "message": "No DMARC policy - email spoofing risk"})

    risk = min(risk, 100)
    grade = "A"
    if risk >= 80: grade = "F"
    elif risk >= 60: grade = "D"
    elif risk >= 40: grade = "C"
    elif risk >= 20: grade = "B"

    return {
        "score": risk,
        "grade": grade,
        "issues": issues
    }




def main():
    parser = argparse.ArgumentParser(
        description="KitFind Python Analysis Engine",
        epilog="AUTHORIZED USE ONLY. Only scan systems you own or have permission to assess."
    )
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--module", default="all",
                        choices=["all", "dns", "ssl", "headers", "tech"],
                        help="Module to run (default: all)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if target.startswith("http"):
        domain = urllib.parse.urlparse(target).netloc
    else:
        domain = target

    output = {"target": target, "domain": domain, "timestamp": datetime.now().isoformat()}

    if args.module in ("all", "dns"):
        output["dns"] = analyze_dns(domain)

    if args.module in ("all", "ssl"):
        output["ssl"] = analyze_ssl(domain)

    if args.module in ("all", "headers"):
        output["headers"] = analyze_headers(target)

    if args.module in ("all", "tech"):
        output["tech"] = analyze_tech(target)

    if args.module == "all" and all(k in output for k in ("dns", "ssl", "headers")):
        output["risk"] = calculate_risk(output["dns"], output["ssl"], output["headers"])

    if args.json:
        print(json.dumps(output, indent=2, default=str))
    else:

        print(f"\n  KitFind Python Analyzer — {target}")
        print(f"  {'─' * 50}")

        if "dns" in output:
            dns_data = output["dns"]
            rec_count = sum(len(v) for v in dns_data.get("records", {}).values())
            print(f"  DNS Records   : {rec_count} found")
            email = dns_data.get("email_security", {})
            print(f"  SPF           : {'✓' if email.get('spf') else '✗'}")
            print(f"  DMARC         : {'✓' if email.get('dmarc') else '✗'}")

        if "ssl" in output:
            ssl_data = output["ssl"]
            print(f"  Protocol      : {ssl_data.get('protocol', 'N/A')}")
            days = ssl_data.get("cert", {}).get("days_until_expiry", "N/A")
            print(f"  Cert Expiry   : {days} days")
            issues = ssl_data.get("issues", [])
            print(f"  SSL Issues    : {len(issues)}")

        if "headers" in output:
            print(f"  Header Score  : {output['headers'].get('score', 0)}/100")

        if "risk" in output:
            risk = output["risk"]
            print(f"  Risk Score    : {risk['score']}/100  Grade: {risk['grade']}")

        print()


if __name__ == "__main__":
    main()
