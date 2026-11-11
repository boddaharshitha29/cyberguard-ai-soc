"""
CYBERGUARD AI - Unit & Integration Test Suite for Advanced Modules
Tests Modules 1-9: Alerts, SHAP, PCAP, Geolocation, Firewall, Reports, Timeline, Threshold & Drift.
"""

import os
import sys
import pytest
import numpy as np
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.alert_center import ThreatAlertCenter
from src.explainability import FlowSHAPExplainer
from src.pcap_analyzer import validate_pcap_file, parse_pcap_to_flows
from src.geolocation import resolve_ip_geolocation, build_attack_geolocation_map
from src.firewall_manager import EnterpriseFirewallManager
from src.report_generator import generate_executive_pdf_report, export_flows_to_csv
from src.timeline_analytics import build_traffic_timeline_chart, build_cumulative_mitigation_chart
from src.drift_monitor import ThresholdManager, DriftMonitor
from src.model import DDoSFlowClassifier


@pytest.fixture(scope="session")
def trained_model():
    model_path = os.path.join(BASE_DIR, "models", "rf_ddos_model.joblib")
    return DDoSFlowClassifier.load(model_path)


def test_alert_center_lifecycle():
    ac = ThreatAlertCenter()
    
    # 1. Critical severity for high rate SYN flood
    a1 = ac.record_alert("198.51.100.88", 443, "SYN_Flood", 0.99, 3500.0, 25000.0)
    assert a1["Severity"] == "CRITICAL"
    assert a1["Acknowledged"] is False

    # 2. High severity for UDP flood
    a2 = ac.record_alert("203.0.113.50", 53, "UDP_Flood", 0.95, 2000.0, 40000.0)
    assert a2["Severity"] == "HIGH"

    # 3. Acknowledge
    assert ac.acknowledge_alert(a1["Alert_ID"]) is True
    stats = ac.get_summary_stats()
    assert stats["total"] == 2
    assert stats["unacknowledged"] == 1


def test_shap_explainability(trained_model):
    explainer = FlowSHAPExplainer(trained_model.model, trained_model.feature_names)
    sample_flow = {
        "Flow_Duration": 35000.0,
        "Flow_Packets_Sec": 3500.0,
        "Flow_Bytes_Sec": 189000.0,
        "Fwd_Bwd_Packet_Ratio": 120.0,
        "SYN_Flag_Count": 120,
        "Avg_Packet_Size": 54.0,
        "Total_Fwd_Packets": 120,
        "Total_Bwd_Packets": 1,
        "ACK_Flag_Count": 0,
        "Flow_IAT_Mean": 290.0,
        "Subflow_Fwd_Bytes": 6480.0,
        "Protocol": 6
    }
    explanation = explainer.explain_flow(sample_flow)
    assert "prediction_probability" in explanation
    assert "attributions_dataframe" in explanation
    assert len(explanation["attributions_dataframe"]) == len(trained_model.feature_names)
    
    # Test chart creation
    fig = explainer.create_attribution_plot(explanation["attributions_dataframe"])
    assert fig is not None


def test_pcap_analyzer():
    # 1. Validation test
    valid_header = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20
    is_valid, msg = validate_pcap_file(valid_header)
    assert is_valid is True

    bad_header = b"NOT_A_PCAP_HEADER"
    is_bad, _ = validate_pcap_file(bad_header)
    assert is_bad is False

    # 2. Parsing sample test PCAP
    pcap_sample = os.path.join(BASE_DIR, "data", "sample_pcaps", "syn_flood_sample.pcap")
    if os.path.exists(pcap_sample):
        df_flows, telemetry = parse_pcap_to_flows(pcap_sample)
        assert len(df_flows) > 0
        assert "Flow_Packets_Sec" in df_flows.columns
        assert telemetry["total_packets"] > 0


def test_geolocation():
    # Private IP
    priv_geo = resolve_ip_geolocation("192.168.1.105")
    assert priv_geo["is_internal"] is True
    assert priv_geo["country"] == "Internal Network"

    # Public IP
    pub_geo = resolve_ip_geolocation("198.51.100.84")
    assert pub_geo["is_internal"] is False
    assert "lat" in pub_geo and "lon" in pub_geo

    # Geolocation map
    fig = build_attack_geolocation_map([{"Source_IP": "198.51.100.84", "Verdict": "Attack", "Attack_Type": "SYN_Flood"}])
    assert fig is not None


def test_firewall_manager_manual_approval():
    fwm = EnterpriseFirewallManager()

    # 1. Whitelist protection
    res_wl = fwm.stage_mitigation("192.168.1.1", 80, 6, "SYN_Flood", 0.99, 5000.0)
    assert res_wl["status"] == "WHITELISTED_BYPASS"
    assert "192.168.1.1" not in fwm.active_blocks

    # 2. Staged pending mitigation
    item = fwm.stage_mitigation("198.51.100.22", 443, 6, "SYN_Flood", 0.99, 4500.0)
    assert item["Status"] == "PENDING_APPROVAL"
    assert "198.51.100.22" not in fwm.active_blocks  # NOT blocked automatically!

    # 3. Explicit operator approval
    rule_id = item["Rule_ID"]
    approved = fwm.approve_rule(rule_id, operator="Test-Admin")
    assert approved is True
    assert "198.51.100.22" in fwm.active_blocks

    # 4. Unblock
    unblocked = fwm.unblock_ip("198.51.100.22", operator="Test-Admin")
    assert unblocked is True
    assert "198.51.100.22" not in fwm.active_blocks

    # 5. Export bash script
    fwm.manual_block_ip("203.0.113.99", reason="Test block")
    script = fwm.export_bash_script()
    assert "iptables" in script
    assert "203.0.113.99" in script


def test_report_generator():
    summary_stats = {"total_flows": 2500, "attacks_blocked": 1250}
    top_threats = [{"Source_IP": "198.51.100.84", "Attack_Type": "SYN_Flood", "Target_Port": 443, "Packets_Sec": 3200.0}]
    model_metrics = {"accuracy": 0.9996, "precision": 0.9996, "recall": 0.9996, "f1_score": 0.9996, "roc_auc": 1.0}

    pdf_bytes = generate_executive_pdf_report(summary_stats, top_threats, model_metrics)
    assert len(pdf_bytes) > 500
    assert pdf_bytes[:4] == b"%PDF"

    csv_data = export_flows_to_csv(top_threats)
    assert "198.51.100.84" in csv_data


def test_timeline_and_drift():
    # Timeline
    fig_time = build_traffic_timeline_chart([])
    assert fig_time is not None

    fig_cum = build_cumulative_mitigation_chart([])
    assert fig_cum is not None

    # Threshold
    tm = ThresholdManager(default_threshold=0.50)
    verdict, is_atk, _ = tm.evaluate_verdict(0.40)
    assert is_atk is False
    tm.set_threshold(0.30)
    verdict_low, is_atk_low, _ = tm.evaluate_verdict(0.40)
    assert is_atk_low is True  # Changed from Benign to Attack due to lower threshold!

    # Drift Monitor
    df_base = pd.DataFrame({"Flow_Packets_Sec": np.random.normal(15, 2, 500)})
    df_live = pd.DataFrame({"Flow_Packets_Sec": np.random.normal(15, 2, 500)})
    dm = DriftMonitor(df_base)
    res_stable = dm.check_drift(df_live, "Flow_Packets_Sec")
    assert res_stable["status"] == "STABLE"
