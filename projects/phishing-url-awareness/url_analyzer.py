
from urllib.parse import urlsplit
import ipaddress
import re


def analyze_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        return ["Error: URL is empty."]

    # Parse the URL without visiting it.
    candidate = raw_url
    if "://" not in candidate:
        candidate = "//" + candidate

    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        scheme = parts.scheme.lower()
    except ValueError:
        return ["Error: URL could not be parsed safely."]

    findings = []

    if not hostname:
        return ["Warning: No hostname could be identified."]

    findings.append(f"Hostname: {hostname}")
    findings.append(f"Scheme: {scheme or 'not specified'}")

    if "@" in parts.netloc:
        findings.append(
            "Warning: '@' appears in the authority section."
        )

    if scheme == "http":
        findings.append(
            "Caution: HTTP does not encrypt the connection."
        )

    try:
        ipaddress.ip_address(hostname)
        findings.append(
            "Caution: Hostname is an IP address."
        )
    except ValueError:
        pass

    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append(
            "Caution: Internationalized domain encoding detected."
        )

    if re.search(r"%[0-9a-fA-F]{2}", raw_url):
        findings.append(
            "Note: Percent-encoded characters detected."
        )

    findings.append(
        "Reminder: These indicators do not prove a URL is malicious."
    )

    return findings


if __name__ == "__main__":
    sample = "https://example.com@fake-login.example.net/account"

    for finding in analyze_url(sample):
        print(finding)
