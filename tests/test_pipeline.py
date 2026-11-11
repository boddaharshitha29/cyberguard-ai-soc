"""
MLCS PBL - DDoS Detection Using Flow Data
Unit and Pipeline Integration Tests
"""

import os
import sys
import pytest
import numpy as np
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.data_generator import generate_flow_dataset
from src.preprocessing import clean_flow_dataframe, prepare_flow_data, KEY_REVIEW1_FEATURES, ALL_FLOW_FEATURES
from src.model import DDoSFlowClassifier
from src.detector import FlowMitigationEngine


@pytest.fixture(scope="session")
def sample_data():
    df = generate_flow_dataset(n_samples=1000, benign_ratio=0.5, random_state=42)
    return df


def test_data_generation_structure(sample_data):
    assert len(sample_data) == 1000
    assert "Binary_Label" in sample_data.columns
    assert "Attack_Type" in sample_data.columns
    for feat in KEY_REVIEW1_FEATURES:
        assert feat in sample_data.columns
    
    benign_count = (sample_data["Binary_Label"] == 0).sum()
    attack_count = (sample_data["Binary_Label"] == 1).sum()
    assert benign_count == 500
    assert attack_count == 500


def test_clean_flow_dataframe():
    bad_df = pd.DataFrame({
        "Flow_Packets_Sec": [10.0, np.inf, 20.0, np.nan],
        "SYN_Flag_Count": [1, 50, 0, 1]
    })
    cleaned = clean_flow_dataframe(bad_df)
    assert not np.isinf(cleaned["Flow_Packets_Sec"]).any()
    assert not cleaned["Flow_Packets_Sec"].isnull().any()


def test_model_training_and_latency(sample_data, tmp_path):
    csv_path = tmp_path / "test_flows.csv"
    sample_data.to_csv(csv_path, index=False)

    X_train, X_test, y_train, y_test, feats, _ = prepare_flow_data(
        csv_path=str(csv_path),
        feature_cols=KEY_REVIEW1_FEATURES,
        target_col="Binary_Label",
        test_size=0.25,
        random_state=42,
        scale_features=False
    )

    clf = DDoSFlowClassifier(n_estimators=30, max_depth=8, random_state=42, feature_names=feats)
    clf.fit(X_train, y_train, feature_names=feats)
    assert clf.is_fitted

    metrics = clf.evaluate(X_test, y_test)
    assert metrics["accuracy"] >= 0.95
    assert metrics["precision"] >= 0.95
    assert metrics["recall"] >= 0.95
    assert metrics["f1_score"] >= 0.95
    assert metrics["detection_latency_per_flow_us"] < 500.0  # Ultra-low latency requirement

    fi_df = clf.get_feature_importances()
    assert len(fi_df) == len(KEY_REVIEW1_FEATURES)
    assert np.isclose(fi_df["Importance"].sum(), 1.0)


def test_mitigation_engine():
    model_path = os.path.join(BASE_DIR, "models", "rf_ddos_model.joblib")
    assert os.path.exists(model_path), "Model must exist before testing engine."

    engine = FlowMitigationEngine(model_path)
    
    # Test SYN flood flow
    attack_flow = {
        "Flow_Duration": 25000.0,
        "Flow_Packets_Sec": 2500.0,
        "Flow_Bytes_Sec": 135000.0,
        "Fwd_Bwd_Packet_Ratio": 50.0,
        "SYN_Flag_Count": 45,
        "Avg_Packet_Size": 54.0,
        "Total_Fwd_Packets": 60,
        "Total_Bwd_Packets": 1,
        "ACK_Flag_Count": 0,
        "Flow_IAT_Mean": 400.0,
        "Subflow_Fwd_Bytes": 3240.0,
        "Protocol": 6,
        "Src_IP": "198.51.100.44",
        "Dst_Port": 80
    }
    result = engine.score_single_flow(attack_flow)
    assert result["is_attack"] is True
    assert result["prediction"] == "Attack"
    assert result["mitigation"]["action"] == "BLOCK_AND_DROP"
    assert "iptables" in result["mitigation"]["firewall_rules"]
    assert "198.51.100.44" in result["mitigation"]["firewall_rules"]["iptables"]

    # Test Benign flow
    benign_flow = {
        "Flow_Duration": 3500000.0,
        "Flow_Packets_Sec": 12.0,
        "Flow_Bytes_Sec": 7500.0,
        "Fwd_Bwd_Packet_Ratio": 1.1,
        "SYN_Flag_Count": 1,
        "Avg_Packet_Size": 625.0,
        "Total_Fwd_Packets": 22,
        "Total_Bwd_Packets": 20,
        "ACK_Flag_Count": 15,
        "Flow_IAT_Mean": 85000.0,
        "Subflow_Fwd_Bytes": 11000.0,
        "Protocol": 6,
        "Src_IP": "192.168.1.55",
        "Dst_Port": 443
    }
    benign_result = engine.score_single_flow(benign_flow)
    assert benign_result["is_attack"] is False
    assert benign_result["prediction"] == "Benign"
    assert benign_result["mitigation"]["action"] == "FORWARD_ALLOWED"
