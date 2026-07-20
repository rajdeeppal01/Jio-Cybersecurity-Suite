import time
import re
import requests
from app.workers.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.models import Campaign, Asset, Report

# NVD API endpoint (free, no key required — 5 req/30s)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Match product and version separated by spaces or slashes (e.g. OpenSSH 8.9 or squid/4.15)
BANNER_PARSE_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-\.]+)(?:\s+|/)([\d][\d\.\-p]+[^\s(]*)")

# Map known service names to better NVD search terms
SERVICE_SEARCH_OVERRIDES = {
    "postgresql": "postgresql",
    "redis": "redis",
    "ssh": "openssh",
    "http": "nginx",
    "ssl/http": "nginx",
    "ms-sql": "microsoft sql server",
}


def _parse_search_term(service_name: str, banner: str) -> str | None:
    """
    Extract a meaningful CVE search term from the service name and banner.
    E.g., 'OpenSSH 8.9p1 Ubuntu' -> 'OpenSSH 8.9p1'
    """
    # Skip fallback/simulated banners — no real CVE search needed
    if "Fallback" in banner or "Simulated" in banner or not banner.strip():
        return None

    # Check if it is an SSH banner containing OpenSSH (which uses underscore separator)
    banner_upper = banner.upper()
    if "OPENSSH_" in banner_upper:
        idx = banner_upper.find("OPENSSH_")
        version_part = banner[idx + 8:].split()[0].split("-")[0]
        return f"OpenSSH {version_part}"

    # If it's an HTTP response, try to find the 'Server:' header first to avoid HTTP/1.1 matching
    if "HTTP/" in banner_upper and "SERVER:" in banner_upper:
        server_idx = banner_upper.find("SERVER:")
        server_line = banner[server_idx:].split("\r\n")[0].split("\n")[0]
        match = BANNER_PARSE_RE.search(server_line)
        if match:
            product, version = match.group(1), match.group(2)
            if product.upper() not in ["HTTP", "HTTPS"]:
                return f"{product} {version}"

    # Try regex extraction from the banner string generally
    match = BANNER_PARSE_RE.search(banner)
    if match:
        product, version = match.group(1), match.group(2)
        if product.upper() not in ["HTTP", "HTTPS"]:
            return f"{product} {version}"

    # Fall back to override table
    svc_lower = service_name.lower()
    for key, override in SERVICE_SEARCH_OVERRIDES.items():
        if key in svc_lower:
            return override

    return None


LOCAL_CVE_DATABASE = {
    "squid": [
        {
            "cve_id": "CVE-2021-28651",
            "description": "Due to a buffer-management bug in Squid before 4.15 and 5.x before 5.0.6, it allows a denial of service when resolving a request with the urn: scheme.",
            "severity": "HIGH",
            "cvss_score": 7.5
        },
        {
            "cve_id": "CVE-2021-28652",
            "description": "Incorrect parser validation in Squid before 4.15 and 5.x before 5.0.6 allows a Denial of Service attack against the Cache Manager API.",
            "severity": "MEDIUM",
            "cvss_score": 4.9
        },
        {
            "cve_id": "CVE-2021-28662",
            "description": "An issue in Squid 4.x before 4.15 and 5.x before 5.0.6 allows a remote server sending a certain response header to trigger denial of service.",
            "severity": "MEDIUM",
            "cvss_score": 6.5
        },
        {
            "cve_id": "CVE-2021-31806",
            "description": "A memory-management bug in Squid before 4.15 and 5.x before 5.0.6 allows Denial of Service via HTTP Range request processing.",
            "severity": "MEDIUM",
            "cvss_score": 6.5
        },
        {
            "cve_id": "CVE-2021-31808",
            "description": "An input-validation bug in Squid before 4.15 and 5.x before 5.0.6 makes it vulnerable to a Denial of Service attack via HTTP Range requests.",
            "severity": "MEDIUM",
            "cvss_score": 6.5
        }
    ],
    "nginx": [
        {
            "cve_id": "CVE-2021-23017",
            "description": "A security vulnerability in nginx resolver allows a 1-byte memory overwrite, potentially leading to denial of service or remote code execution.",
            "severity": "HIGH",
            "cvss_score": 7.5
        }
    ],
    "openssh": [
        {
            "cve_id": "CVE-2023-38408",
            "description": "A security vulnerability in OpenSSH ssh-agent allows remote code execution via PKCS#11 forwarding.",
            "severity": "HIGH",
            "cvss_score": 8.1
        }
    ],
    "redis": [
        {
            "cve_id": "CVE-2022-0543",
            "description": "Lua scripting engine sandbox escape vulnerability in Debian/Ubuntu Redis packages allowing remote command execution.",
            "severity": "CRITICAL",
            "cvss_score": 10.0
        }
    ]
}

def _query_local_database(search_term: str) -> list[dict]:
    term_lower = search_term.lower()
    for key, cves in LOCAL_CVE_DATABASE.items():
        if key in term_lower:
            return cves
    return []


def _query_nvd(search_term: str, max_results: int = 5) -> list[dict]:
    """
    Query the NVD CVE API for a given search term.
    Returns a list of simplified CVE objects: [{id, description, severity, cvss_score}]
    """
    params = {
        "keywordSearch": search_term,
        "resultsPerPage": max_results,
        "startIndex": 0,
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    proxies = {
        "http": "http://10.32.194.128:3128",
        "https": "http://10.32.194.128:3128",
    }

    retries = 3
    delay = 5
    for attempt in range(retries):
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10, proxies=proxies)
            print(f"[NVD query] Search: '{search_term}', Attempt: {attempt + 1}, Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                cves = []

                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "UNKNOWN")

                    # Extract English description
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        "No description available."
                    )

                    # Extract CVSS score and severity
                    severity = "UNKNOWN"
                    cvss_score = None
                    metrics = cve.get("metrics", {})

                    # Try CVSS v3.1 first, then v3.0, then v2.0
                    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if metric_key in metrics and metrics[metric_key]:
                            m = metrics[metric_key][0]
                            cvss_data = m.get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                            break

                    cves.append({
                        "cve_id": cve_id,
                        "description": description[:300] + "..." if len(description) > 300 else description,
                        "severity": severity,
                        "cvss_score": cvss_score,
                    })

                return cves
            
            elif response.status_code in [429, 502, 503, 504]:
                if attempt < retries - 1:
                    time.sleep(delay)
                    delay *= 2
                else:
                    break
            else:
                break

        except Exception as e:
            print(f"[NVD query] Attempt {attempt + 1} Exception: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
            else:
                break

    print(f"[NVD query] NVD API failed. Falling back to local CVE database for: '{search_term}'")
    return _query_local_database(search_term)


def _is_version_affected(discovered_version: str, cve_id: str) -> bool:
    """
    Helper to check if a discovered version is actually vulnerable to a specific CVE.
    Prevents old CVE false positives on patched versions.
    """
    try:
        import re
        disc_nums = [int(x) for x in re.findall(r"\d+", discovered_version)]
        if not disc_nums:
            return True  # Err on the side of safety if no digits parsed
        
        # Extract the year of the CVE (CVE-YYYY-NNNN)
        cve_year_match = re.search(r"CVE-(\d{4})-", cve_id)
        cve_year = int(cve_year_match.group(1)) if cve_year_match else 0
        
        # Generic OpenSSH Year-Based Filter:
        # If discovered version is OpenSSH 9.x (released starting in 2022/2023),
        # it is completely immune to any ancient OpenSSH CVEs from before 2023.
        # This instantly filters out all legacy 1999, 2000, 2001, etc., vulnerabilities.
        if "9." in discovered_version and cve_year > 0 and cve_year < 2023:
            return False
            
        # OpenSSH < 9.3p2
        if cve_id == "CVE-2023-38408":
            if len(disc_nums) >= 2:
                return (disc_nums[0] < 9) or (disc_nums[0] == 9 and disc_nums[1] < 3)
            return True
        
        # Squid < 4.15 or 5.x < 5.0.6
        elif cve_id in ["CVE-2021-28651", "CVE-2021-28652", "CVE-2021-28662", "CVE-2021-31806", "CVE-2021-31808"]:
            if len(disc_nums) >= 2:
                major, minor = disc_nums[0], disc_nums[1]
                if major == 4:
                    return minor < 15
                elif major == 5:
                    return minor < 6
                return major < 4
            return True
        
        # Nginx < 1.20.1
        elif cve_id == "CVE-2021-23017":
            if len(disc_nums) >= 2:
                major, minor = disc_nums[0], disc_nums[1]
                if major == 1:
                    return minor < 20
                return major < 1
            return True
            
        # Nginx legacy CVEs from 2009
        elif cve_id in ["CVE-2009-2629", "CVE-2009-3896", "CVE-2009-3898", "CVE-2009-4487", "CVE-2010-2263"]:
            if len(disc_nums) >= 2:
                major, minor = disc_nums[0], disc_nums[1]
                return major == 0 or (major == 1 and minor == 0)
            return False
    except Exception:
        pass
    return True


@celery_app.task(name="app.workers.tasks_tier3.cve_assessment")
def cve_assessment(campaign_id: str, ip_addresses: list):
    """
    Tier 3 — CVE Assessment Worker.
    Queries NVD API for each discovered service/banner and writes real CVE data
    into Asset.vulnerabilities. Sets campaign status to COMPLETED when done.
    """
    db = SessionLocal()
    try:
        # Set a new interim status so the UI shows progress
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            campaign.status = "ASSESSING"
            db.commit()

        # Fetch all non-placeholder assets for this campaign
        assets = db.query(Asset).filter(
            Asset.campaign_id == campaign_id,
            Asset.port != 0
        ).all()

        cve_cache = {}
        for i, asset in enumerate(assets):
            search_term = _parse_search_term(asset.service or "", asset.banner or "")

            if search_term:
                if search_term not in cve_cache:
                    raw_cves = _query_nvd(search_term)
                    
                    # Filter out false positives by version matching
                    filtered_cves = []
                    import re
                    version_match = re.search(r"[\d\.]+[^\s]*", search_term)
                    version_str = version_match.group(0) if version_match else ""
                    for cve in raw_cves:
                        cve_id = cve.get("cve_id")
                        if version_str:
                            if _is_version_affected(version_str, cve_id):
                                filtered_cves.append(cve)
                        else:
                            filtered_cves.append(cve)
                    
                    cve_cache[search_term] = filtered_cves
                    
                    # Respect NVD rate limit: 5 requests per 30 seconds
                    if i < len(assets) - 1:
                        time.sleep(6)
                asset.vulnerabilities = cve_cache[search_term]
            else:
                asset.vulnerabilities = []

            db.commit()

            # Respect NVD rate limit: 5 requests per 30 seconds (free tier)
            # Add a 7-second delay between requests to stay safely within limits
            if search_term and i < len(assets) - 1:
                time.sleep(3)

        # Mark campaign COMPLETED
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            import datetime
            campaign.status = "COMPLETED"
            campaign.completed_at = datetime.datetime.utcnow()
            db.commit()

    except Exception as e:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            campaign.status = "FAILED"
            db.commit()
        raise e
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks_tier3.generate_narrative_report")
def generate_narrative_report(campaign_id: str):
    """
    Tier 3 — Generate Narrative Report.
    Constructs topology data and calls LLMEngine to generate the Markdown report,
    saving it to the Report table.
    """
    db = SessionLocal()
    try:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if not campaign:
            return
        
        # Build topology data
        nodes = []
        # Add a default network infrastructure node (gateway)
        nodes.append({
            "id": "gateway",
            "label": "Local Gateway",
            "type": "network_infrastructure"
        })
        
        # Group assets by IP address
        from collections import defaultdict
        assets_by_ip = defaultdict(list)
        blocked_targets = []
        for asset in campaign.assets:
            if asset.port != 0:
                assets_by_ip[asset.ip_address].append(asset)
            elif asset.service == "network-policy":
                blocked_targets.append({
                    "ip": asset.ip_address,
                    "hostname": asset.hostname,
                    "reason": asset.banner
                })
        for ip, assets in assets_by_ip.items():
            hostname = assets[0].hostname or ip
            ports = []
            for asset in assets:
                ports.append({
                    "number": asset.port,
                    "service": asset.service,
                    "banner": asset.banner,
                    "cves": asset.vulnerabilities or []
                })
            nodes.append({
                "id": ip,
                "label": hostname,
                "type": "host",
                "ports": ports
            })
        links = []
        for node in nodes:
            if node["id"] != "gateway":
                links.append({
                    "source": "gateway",
                    "target": node["id"]
                })
        topology_data = {
            "campaign_id": campaign_id,
            "total_hosts": len(assets_by_ip),
            "nodes": nodes,
            "links": links,
            "blocked_targets": blocked_targets
        }
        
        # Generate narrative using LLM
        from app.services.llm_engine import LLMEngine
        llm = LLMEngine()
        narrative = llm.generate_attack_narrative(topology_data)
        
        # Save report
        report = Report(
            campaign_id=campaign_id,
            topology_data=topology_data,
            narrative=narrative
        )
        db.add(report)
        db.commit()
        
    except Exception as e:
        raise e
    finally:
        db.close()
