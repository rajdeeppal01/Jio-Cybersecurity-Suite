from sqlalchemy.orm import Session
from app.models.models import Asset

class GraphPreprocessor:
    @staticmethod
    def process_campaign_assets(campaign_id: str, db: Session) -> dict:
        """
        Aggregates discovered assets for a campaign into a compressed,
        topological JSON network graph (nodes and edges).
        """
        assets = db.query(Asset).filter(Asset.campaign_id == campaign_id).all()
        
        nodes = []
        edges = []
        
        # Unique IPs discovered
        unique_ips = set()
        
        # Build Nodes
        for asset in assets:
            if asset.ip_address not in unique_ips:
                unique_ips.add(asset.ip_address)
                nodes.append({
                    "id": asset.ip_address,
                    "label": asset.hostname or asset.ip_address,
                    "type": "host",
                    "ports": []
                })
            
            # Find the host node and add the open port details to its ports array
            for node in nodes:
                if node["id"] == asset.ip_address and asset.port > 0:
                    node["ports"].append({
                        "number": asset.port,
                        "service": asset.service,
                        "banner": asset.banner,
                        "cves": asset.vulnerabilities or []
                    })
        
        # Build Edges representing communication links/relations
        # For simulation, we connect all hosts to a logical gateway / subnet root
        gateway_ip = "192.168.1.1" # Example default gateway
        nodes.append({
            "id": gateway_ip,
            "label": "Local Gateway",
            "type": "network_infrastructure",
            "ports": []
        })
        
        for ip in unique_ips:
            edges.append({
                "source": gateway_ip,
                "target": ip,
                "relation": "routes_to",
                "label": "LAN Route"
            })
            
        return {
            "campaign_id": campaign_id,
            "nodes": nodes,
            "edges": edges,
            "total_hosts": len(unique_ips)
        }
