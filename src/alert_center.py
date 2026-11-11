"""
CYBERGUARD AI - Threat Alert Center
Module 1: Real-Time Threat Alerting & Incident History

Tracks network threat incidents with severity classification (CRITICAL, HIGH, MEDIUM, LOW),
acknowledgment workflows, filtering, and alert retention.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd


class ThreatAlertCenter:
    """
    Manages threat alert lifecycles, severities, and history.
    """
    def __init__(self, max_history: int = 500):
        self.max_history = max_history
        self.alerts: List[Dict[str, Any]] = []

    def classify_severity(self, attack_type: str, confidence: float, packets_sec: float) -> str:
        """
        Calculates severity level based on volumetric intensity and attack profile:
          - CRITICAL: Volumetric SYN flood or high packet rate (>2000 pps) with >95% confidence
          - HIGH: UDP floods or sustained HTTP floods
          - MEDIUM: Standard anomalous floods or high rate deviations
          - LOW: Borderline anomalous flows
        """
        if attack_type == "SYN_Flood" and (packets_sec > 1500 or confidence >= 0.95):
            return "CRITICAL"
        elif attack_type == "UDP_Flood" or packets_sec > 2500:
            return "HIGH"
        elif attack_type == "HTTP_Flood":
            return "HIGH" if packets_sec > 500 else "MEDIUM"
        elif confidence >= 0.85:
            return "MEDIUM"
        else:
            return "LOW"

    def record_alert(
        self,
        src_ip: str,
        dst_port: int,
        attack_type: str,
        confidence: float,
        packets_sec: float,
        flow_duration_us: float,
        mitigation_status: str = "Pending Approval"
    ) -> Dict[str, Any]:
        """
        Generates and logs an alert.
        """
        alert_id = f"ALT-{datetime.now().strftime('%m%d%H%M%S')}-{len(self.alerts) + 1:03d}"
        severity = self.classify_severity(attack_type, confidence, packets_sec)

        alert_entry = {
            "Alert_ID": alert_id,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source_IP": src_ip,
            "Target_Port": dst_port,
            "Attack_Type": attack_type,
            "Severity": severity,
            "Confidence": round(confidence * 100, 2),
            "Packet_Rate": round(packets_sec, 2),
            "Duration_us": round(flow_duration_us, 2),
            "Mitigation_Status": mitigation_status,
            "Acknowledged": False
        }

        self.alerts.insert(0, alert_entry)
        if len(self.alerts) > self.max_history:
            self.alerts.pop()

        return alert_entry

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged by SOC operator."""
        for a in self.alerts:
            if a["Alert_ID"] == alert_id:
                a["Acknowledged"] = True
                return True
        return False

    def update_mitigation_status(self, alert_id: str, new_status: str) -> bool:
        """Update the mitigation enforcement status of an alert."""
        for a in self.alerts:
            if a["Alert_ID"] == alert_id:
                a["Mitigation_Status"] = new_status
                return True
        return False

    def get_alerts_dataframe(
        self,
        severity_filter: Optional[str] = None,
        unacknowledged_only: bool = False
    ) -> pd.DataFrame:
        """Returns filtered alert history as a DataFrame."""
        if not self.alerts:
            return pd.DataFrame(columns=[
                "Alert_ID", "Timestamp", "Source_IP", "Target_Port",
                "Attack_Type", "Severity", "Confidence", "Packet_Rate",
                "Duration_us", "Mitigation_Status", "Acknowledged"
            ])

        records = self.alerts
        if severity_filter and severity_filter != "ALL":
            records = [r for r in records if r["Severity"] == severity_filter]
        if unacknowledged_only:
            records = [r for r in records if not r["Acknowledged"]]

        return pd.DataFrame(records)

    def get_summary_stats(self) -> Dict[str, Any]:
        """Returns statistical counts for alerts."""
        df = self.get_alerts_dataframe()
        total = len(df)
        if total == 0:
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "unacknowledged": 0}

        return {
            "total": total,
            "critical": int((df["Severity"] == "CRITICAL").sum()),
            "high": int((df["Severity"] == "HIGH").sum()),
            "medium": int((df["Severity"] == "MEDIUM").sum()),
            "low": int((df["Severity"] == "LOW").sum()),
            "unacknowledged": int((~df["Acknowledged"]).sum())
        }
