"""
CYBERGUARD AI - Advanced SOC REST API
FastAPI Real-Time Flow Scoring, Explainable AI, Threat Alerts & Mitigation Management

Allows SDN Controllers (Ryu, ONOS, OVS) and edge security appliances to:
  - Query Random Forest classifications with custom detection thresholds
  - Retrieve SHAP explainability attributions
  - Manage operator approval queues for firewall drop rules
  - Ingest PCAP network packet captures
  - Access threat alerts and audit reports
"""

import os
import sys
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Response
from pydantic import BaseModel, Field

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.detector import FlowMitigationEngine, stream_flow_generator
from src.alert_center import ThreatAlertCenter
from src.firewall_manager import EnterpriseFirewallManager
from src.explainability import FlowSHAPExplainer
from src.pcap_analyzer import validate_pcap_file, parse_pcap_to_flows
from src.report_generator import generate_executive_pdf_report


app = FastAPI(
    title="CYBERGUARD AI - Enterprise SOC Detection & Defense API",
    description="Advanced AI-powered network traffic classification, TreeSHAP explainability, and autonomous firewall mitigation management.",
    version="2.0.0"
)

# Global instances
MODEL_PATH = os.path.join(BASE_DIR, "models", "rf_ddos_model.joblib")
MULTI_MODEL_PATH = os.path.join(BASE_DIR, "models", "rf_multiclass_model.joblib")
CSV_PATH = os.path.join(BASE_DIR, "data", "raw", "network_flows.csv")

engine: Optional[FlowMitigationEngine] = None
alert_center = ThreatAlertCenter()
firewall_manager = EnterpriseFirewallManager()
shap_explainer: Optional[FlowSHAPExplainer] = None


@app.on_event("startup")
def startup_event():
    global engine, shap_explainer
    if os.path.exists(MODEL_PATH):
        engine = FlowMitigationEngine(MODEL_PATH, MULTI_MODEL_PATH)
        shap_explainer = FlowSHAPExplainer(engine.rf_model.model, engine.rf_model.feature_names)


class FlowPayload(BaseModel):
    Flow_Duration: float = Field(..., example=45000.0, description="Flow duration in microseconds")
    Flow_Packets_Sec: float = Field(..., example=850.5, description="Packet rate (packets/sec)")
    Flow_Bytes_Sec: float = Field(..., example=450000.0, description="Byte rate (bytes/sec)")
    Fwd_Bwd_Packet_Ratio: float = Field(..., example=25.0, description="Ratio of forward packets to backward packets")
    SYN_Flag_Count: int = Field(..., example=45, description="Number of SYN flags observed in flow")
    Avg_Packet_Size: float = Field(..., example=60.0, description="Average packet size in bytes")
    Total_Fwd_Packets: Optional[int] = Field(50, description="Total forward packets")
    Total_Bwd_Packets: Optional[int] = Field(2, description="Total backward packets")
    ACK_Flag_Count: Optional[int] = Field(0, description="Number of ACK flags")
    Flow_IAT_Mean: Optional[float] = Field(500.0, description="Mean inter-arrival time in microseconds")
    Subflow_Fwd_Bytes: Optional[float] = Field(2500.0, description="Subflow forward bytes")
    Protocol: Optional[int] = Field(6, description="IP protocol number (6: TCP, 17: UDP)")
    Src_IP: Optional[str] = Field("198.51.100.25", description="Source IPv4 address")
    Dst_Port: Optional[int] = Field(80, description="Destination port number")
    threshold: Optional[float] = Field(0.50, description="Detection decision threshold")
    explain: Optional[bool] = Field(False, description="Whether to include SHAP feature attribution")


@app.get("/")
def get_info():
    return {
        "platform": "CYBERGUARD AI - Enterprise SOC Platform",
        "version": "2.0.0",
        "model": "Random Forest Ensemble (Supervised)",
        "modules": [
            "Real-Time Threat Alert Center",
            "Explainable AI (SHAP TreeExplainer)",
            "PCAP File Analysis",
            "Attack Geolocation",
            "Firewall Manager with Manual Approvals",
            "Audit Report Generator",
            "Temporal Traffic Analytics",
            "Detection Threshold Tuning",
            "Model Drift Monitor"
        ]
    }


@app.post("/predict_flow")
def predict_flow(payload: FlowPayload):
    if engine is None:
        raise HTTPException(status_code=500, detail="Classifier engine not initialized.")
    flow_data = payload.dict()
    th = flow_data.pop("threshold", 0.50)
    need_explain = flow_data.pop("explain", False)

    result = engine.score_single_flow(flow_data, threshold=th)

    # Log to alert center and firewall queue if attack
    if result["is_attack"]:
        alert = alert_center.record_alert(
            src_ip=flow_data.get("Src_IP", "198.51.100.1"),
            dst_port=int(flow_data.get("Dst_Port", 80)),
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            packets_sec=float(flow_data.get("Flow_Packets_Sec", 0.0)),
            flow_duration_us=float(flow_data.get("Flow_Duration", 0.0))
        )
        mitigation_item = firewall_manager.stage_mitigation(
            src_ip=flow_data.get("Src_IP", "198.51.100.1"),
            dst_port=int(flow_data.get("Dst_Port", 80)),
            proto=int(flow_data.get("Protocol", 6)),
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            packet_rate=float(flow_data.get("Flow_Packets_Sec", 0.0))
        )
        result["alert_id"] = alert["Alert_ID"]
        result["firewall_staged"] = mitigation_item

    # Optional SHAP explanation
    if need_explain and shap_explainer is not None:
        explanation = shap_explainer.explain_flow(flow_data)
        result["shap_explanation"] = {
            "base_value": explanation["base_value"],
            "insights": explanation["insights"],
            "top_attributions": explanation["attributions_dataframe"].to_dict(orient="records")
        }

    return result


@app.get("/alerts")
def get_alerts(severity: Optional[str] = None):
    df_alerts = alert_center.get_alerts_dataframe(severity_filter=severity)
    return {
        "summary": alert_center.get_summary_stats(),
        "alerts": df_alerts.to_dict(orient="records")
    }


@app.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    success = alert_center.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    return {"status": "SUCCESS", "alert_id": alert_id, "acknowledged": True}


@app.get("/firewall/pending")
def get_pending_firewall_rules():
    df_pending = firewall_manager.get_pending_dataframe()
    return {"pending_count": len(df_pending), "rules": df_pending.to_dict(orient="records")}


@app.post("/firewall/approve/{rule_id}")
def approve_firewall_rule(rule_id: str, operator: str = "SOC-Admin"):
    success = firewall_manager.approve_rule(rule_id, operator=operator)
    if not success:
        raise HTTPException(status_code=404, detail="Rule ID not found or already processed")
    return {"status": "ENFORCED", "rule_id": rule_id, "operator": operator}


@app.post("/firewall/reject/{rule_id}")
def reject_firewall_rule(rule_id: str, operator: str = "SOC-Admin", reason: str = "Operator dismissed"):
    success = firewall_manager.reject_rule(rule_id, operator=operator, reason=reason)
    if not success:
        raise HTTPException(status_code=404, detail="Rule ID not found or already processed")
    return {"status": "REJECTED", "rule_id": rule_id, "reason": reason}


@app.get("/firewall/active_blocks")
def get_active_blocks():
    df_blocks = firewall_manager.get_active_blocks_dataframe()
    return {"active_blocks_count": len(df_blocks), "blocks": df_blocks.to_dict(orient="records")}


@app.post("/firewall/unblock/{ip}")
def unblock_ip(ip: str, operator: str = "SOC-Admin"):
    success = firewall_manager.unblock_ip(ip, operator=operator)
    return {"status": "SUCCESS" if success else "NOT_FOUND", "ip": ip}


@app.get("/firewall/export_bash")
def export_firewall_bash():
    script = firewall_manager.export_bash_script()
    return Response(content=script, media_type="text/x-shellscript")


@app.post("/pcap/analyze")
async def analyze_pcap_upload(file: UploadFile = File(...)):
    contents = await file.read()
    is_valid, msg = validate_pcap_file(contents)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    df_flows, telemetry = parse_pcap_to_flows(contents)
    if df_flows.empty:
        return {"status": "EMPTY", "message": "No IP packets found in PCAP capture", "telemetry": telemetry}

    # Score flows
    results = []
    attacks_found = 0
    for _, row in df_flows.iterrows():
        flow_d = row.to_dict()
        res = engine.score_single_flow(flow_d)
        if res["is_attack"]:
            attacks_found += 1
        results.append({
            "src_ip": flow_d.get("Src_IP"),
            "dst_port": flow_d.get("Dst_Port"),
            "protocol": "TCP" if flow_d.get("Protocol") == 6 else "UDP",
            "verdict": res["prediction"],
            "attack_type": res["attack_type"],
            "confidence": round(res["confidence"] * 100, 2),
            "pps": flow_d.get("Flow_Packets_Sec")
        })

    telemetry["attacks_detected"] = attacks_found
    telemetry["benign_flows"] = len(df_flows) - attacks_found
    return {"telemetry": telemetry, "scored_flows_sample": results[:50]}


@app.get("/telemetry")
def get_telemetry():
    if engine is None:
        raise HTTPException(status_code=500, detail="Classifier engine not initialized.")
    return engine.get_telemetry_stats()
