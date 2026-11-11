"""
CYBERGUARD AI - Enterprise Firewall & Mitigation Manager
Module 5: IP Blocking, Whitelisting, and Manual Approval Workflows

Enforces strict human-in-the-loop cybersecurity controls:
No firewall drop rule is executed automatically without explicit operator authorization.
"""

from datetime import datetime
from typing import Dict, Any, List, Set, Optional
import pandas as pd
from src.utils import generate_firewall_rule


class EnterpriseFirewallManager:
    """
    Manages firewall rule approval queues, active enforcement, and trusted whitelists.
    """
    def __init__(self):
        # Whitelist default trusted corporate & DNS subnets
        self.whitelist: Set[str] = {
            "192.168.1.1", "192.168.1.254", "10.0.0.1", "8.8.8.8", "1.1.1.1", "127.0.0.1"
        }
        
        # Pending approval queue: List[Dict]
        self.pending_queue: List[Dict[str, Any]] = []
        
        # Enforced active blocks: Dict[ip -> Dict]
        self.active_blocks: Dict[str, Dict[str, Any]] = {}
        
        # Action audit log
        self.audit_log: List[Dict[str, Any]] = []

    def is_whitelisted(self, ip: str) -> bool:
        """Checks if IP is immune to blocking."""
        return ip in self.whitelist

    def add_to_whitelist(self, ip: str, reason: str = "Admin trusted") -> bool:
        """Adds an IP to the protected whitelist."""
        self.whitelist.add(ip)
        if ip in self.active_blocks:
            del self.active_blocks[ip]
        self._log_audit("WHITELIST_ADD", ip, f"Added to whitelist: {reason}")
        return True

    def remove_from_whitelist(self, ip: str) -> bool:
        """Removes an IP from the whitelist."""
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self._log_audit("WHITELIST_REMOVE", ip, "Removed from whitelist")
            return True
        return False

    def stage_mitigation(
        self,
        src_ip: str,
        dst_port: int,
        proto: int,
        attack_type: str,
        confidence: float,
        packet_rate: float
    ) -> Dict[str, Any]:
        """
        Stages a detected threat for administrator evaluation.
        Does NOT block automatically.
        """
        if self.is_whitelisted(src_ip):
            self._log_audit("WHITELIST_BYPASS", src_ip, f"Threat {attack_type} ignored because IP is whitelisted.")
            return {
                "status": "WHITELISTED_BYPASS",
                "message": f"Source IP {src_ip} is protected by enterprise whitelist."
            }

        rule_id = f"RULE-{datetime.now().strftime('%H%M%S')}-{len(self.pending_queue)+1:02d}"
        rules = generate_firewall_rule(src_ip, dst_port, proto, attack_type)

        item = {
            "Rule_ID": rule_id,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source_IP": src_ip,
            "Target_Port": dst_port,
            "Protocol": "TCP" if proto == 6 else "UDP",
            "Attack_Type": attack_type,
            "Confidence": round(confidence * 100, 2),
            "Packet_Rate": round(packet_rate, 2),
            "iptables_rule": rules["iptables"],
            "openflow_rule": rules["openflow_sdn"],
            "Status": "PENDING_APPROVAL"
        }

        # Avoid duplicate pending rules for the same IP
        existing = [q for q in self.pending_queue if q["Source_IP"] == src_ip and q["Status"] == "PENDING_APPROVAL"]
        if not existing:
            self.pending_queue.insert(0, item)
            self._log_audit("STAGE_PENDING", src_ip, f"Mitigation queued for {attack_type} on port {dst_port}")
        return item

    def approve_rule(self, rule_id: str, operator: str = "Admin") -> bool:
        """
        Explicit operator approval: Enforces the mitigation rule in the active firewall blocklist.
        """
        for item in self.pending_queue:
            if item["Rule_ID"] == rule_id and item["Status"] == "PENDING_APPROVAL":
                item["Status"] = "APPROVED_AND_ENFORCED"
                ip = item["Source_IP"]
                self.active_blocks[ip] = {
                    "Rule_ID": rule_id,
                    "Source_IP": ip,
                    "Target_Port": item["Target_Port"],
                    "Attack_Type": item["Attack_Type"],
                    "Enforced_At": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Operator": operator,
                    "iptables_rule": item["iptables_rule"],
                    "openflow_rule": item["openflow_rule"]
                }
                self._log_audit("RULE_ENFORCED", ip, f"Mitigation approved by {operator}")
                return True
        return False

    def reject_rule(self, rule_id: str, operator: str = "Admin", reason: str = "False positive or test") -> bool:
        """
        Operator rejection: Dismisses the proposed firewall rule without blocking.
        """
        for item in self.pending_queue:
            if item["Rule_ID"] == rule_id and item["Status"] == "PENDING_APPROVAL":
                item["Status"] = "REJECTED"
                self._log_audit("RULE_REJECTED", item["Source_IP"], f"Rejected by {operator}: {reason}")
                return True
        return False

    def unblock_ip(self, ip: str, operator: str = "Admin") -> bool:
        """Removes an active block."""
        if ip in self.active_blocks:
            del self.active_blocks[ip]
            self._log_audit("UNBLOCK", ip, f"Unblocked by {operator}")
            return True
        return False

    def manual_block_ip(self, ip: str, reason: str = "Manual admin block", dst_port: int = 80, operator: str = "Admin") -> bool:
        """Directly blocks an IP manually."""
        if self.is_whitelisted(ip):
            return False
        rules = generate_firewall_rule(ip, dst_port, 6, "Manual_Block")
        self.active_blocks[ip] = {
            "Rule_ID": f"MANUAL-{datetime.now().strftime('%H%M%S')}",
            "Source_IP": ip,
            "Target_Port": dst_port,
            "Attack_Type": "Manual Admin Block",
            "Enforced_At": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Operator": operator,
            "iptables_rule": rules["iptables"],
            "openflow_rule": rules["openflow_sdn"]
        }
        self._log_audit("MANUAL_BLOCK", ip, f"Manually blocked by {operator}: {reason}")
        return True

    def _log_audit(self, action: str, target_ip: str, details: str):
        self.audit_log.insert(0, {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Action": action,
            "Target_IP": target_ip,
            "Details": details
        })
        if len(self.audit_log) > 300:
            self.audit_log.pop()

    def get_pending_dataframe(self) -> pd.DataFrame:
        pending = [q for q in self.pending_queue if q["Status"] == "PENDING_APPROVAL"]
        return pd.DataFrame(pending)

    def get_active_blocks_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(list(self.active_blocks.values()))

    def get_audit_log_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(self.audit_log)

    def export_bash_script(self) -> str:
        """Generates full executable deployment script for Linux iptables."""
        lines = [
            "#!/bin/bash",
            "# CYBERGUARD AI - Automated Firewall Rule Deployment Script",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "# Explicit Operator Approvals Enforced",
            "",
            "# Flush previous DDoS chain",
            "iptables -N CYBERGUARD_DDOS 2>/dev/null || iptables -F CYBERGUARD_DDOS",
            "iptables -D INPUT -j CYBERGUARD_DDOS 2>/dev/null",
            "iptables -I INPUT 1 -j CYBERGUARD_DDOS",
            ""
        ]
        for ip, blk in self.active_blocks.items():
            lines.append(f"# Block: {blk['Attack_Type']} ({ip}) - Enforced by {blk['Operator']}")
            lines.append(blk['iptables_rule'].replace("-I INPUT 1", "-A CYBERGUARD_DDOS"))
        lines.append("\necho '[+] CYBERGUARD AI Firewall Rules Deployed Successfully.'\n")
        return "\n".join(lines)
