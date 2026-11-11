"""
MLCS PBL - DDoS Detection Using Flow Data
Utility Module

Provides network address generators, firewall rule formatters,
and flow data serialization helpers.
"""

import random
import ipaddress
from typing import Dict, Any


def generate_random_ip(is_attack: bool = False, attack_type: str = "Benign") -> str:
    """Generate realistic IPv4 addresses for demonstration."""
    if is_attack:
        if attack_type == "SYN_Flood":
            # Spoofed disparate IPs
            return f"198.51.100.{random.randint(2, 254)}"
        elif attack_type == "UDP_Flood":
            return f"203.0.113.{random.randint(2, 254)}"
        else:
            return f"45.33.{random.randint(10, 80)}.{random.randint(2, 254)}"
    else:
        # Legitimate corporate / consumer IPs
        subnets = ["10.0.1.", "172.16.5.", "192.168.1.", "142.250.190."]
        return random.choice(subnets) + str(random.randint(2, 250))


def generate_firewall_rule(src_ip: str, dst_port: int, protocol_num: int, attack_type: str) -> Dict[str, str]:
    """
    Generate actionable SDN OpenFlow and Linux iptables firewall mitigation rules.
    """
    proto_str = "tcp" if protocol_num == 6 else ("udp" if protocol_num == 17 else "ip")
    
    iptables_rule = f"iptables -I INPUT 1 -s {src_ip} -p {proto_str} --dport {dst_port} -m comment --comment 'DDoS-RF-Mitigation: {attack_type}' -j DROP"
    openflow_rule = f"ovs-ofctl add-flow br0 priority=50000,ip,nw_src={src_ip},nw_proto={protocol_num},tp_dst={dst_port},actions=drop"
    
    return {
        "iptables": iptables_rule,
        "openflow_sdn": openflow_rule
    }
