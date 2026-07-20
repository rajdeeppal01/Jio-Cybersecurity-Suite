import socket
import ipaddress
from urllib.parse import urlparse
from app.workers.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.models import Campaign, Asset


def _resolve_target(target: str) -> list[str]:
    """
    Extract IP/host from input (supporting URLs, ports, IPv6 brackets)
    and resolve to a list of IP addresses (supporting IPv4 and IPv6).
    """
    clean_target = target.strip()

    # 1. Parse as URL if scheme exists
    if "://" in clean_target:
        try:
            parsed = urlparse(clean_target)
            clean_target = parsed.netloc or parsed.path
        except Exception:
            pass

    # 2. Extract host from bracketed IPv6 (e.g. [2405:200:1413::42c5]:7090)
    if "[" in clean_target and "]" in clean_target:
        start = clean_target.find("[")
        end = clean_target.find("]")
        clean_target = clean_target[start + 1:end]
    else:
        # Strip port if present (e.g., example.com:8080 or 192.168.1.1:8000)
        if ":" in clean_target and clean_target.count(":") == 1:
            clean_target = clean_target.split(":")[0]

    # 3. Check if target is a direct IP (IPv4 or IPv6)
    try:
        ipaddress.ip_address(clean_target)
        return [clean_target]
    except ValueError:
        pass

    # 4. Direct DNS resolution is blocked in this network environment
    # (only proxy-routed HTTP/HTTPS traffic has outbound access). Rather than
    # silently falling back to 127.0.0.1 and scanning the wrong target, pass
    # the hostname through as-is. Downstream proxy-aware probes (see
    # tasks_tier2._grab_banner_via_proxy) resolve and connect via the proxy,
    # which handles DNS resolution on our behalf.
    return [clean_target]


@celery_app.task(name="app.workers.tasks_tier1.passive_recon")
def passive_recon(campaign_id: str, target: str):
    db = SessionLocal()
    try:
        # Update campaign status
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            campaign.status = "RUNNING"
            db.commit()

        # Discover all IPs for the target using multi-record DNS resolution
        discovered_ips = _resolve_target(target)

        # Log discovered hosts as initial placeholder assets
        for ip in discovered_ips:
            asset = Asset(
                campaign_id=campaign_id,
                ip_address=ip,
                hostname=ip,
                port=0,
                service="ping",
                banner="Target queued for proxy-based scanning"
            )
            db.add(asset)
        db.commit()

        # Trigger Tier 2 Active Mapping
        from app.workers.tasks_tier2 import active_mapping
        active_mapping.delay(campaign_id, discovered_ips)

    except Exception as e:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            campaign.status = "FAILED"
            db.commit()
        raise e
    finally:
        db.close()
