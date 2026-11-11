"""
MLCS PBL - DDoS Detection Using Flow Data
Preprocessing Module

Handles data sanitization, infinite/NaN handling, feature selection,
train-test splitting with stratification, and feature scaling.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, List, Optional
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, RobustScaler


# The Key Flow Features explicitly specified in Review-1
KEY_REVIEW1_FEATURES = [
    "Flow_Duration",
    "Flow_Packets_Sec",
    "Flow_Bytes_Sec",
    "Fwd_Bwd_Packet_Ratio",
    "SYN_Flag_Count",
    "Avg_Packet_Size"
]

# Extended Flow Features for in-depth analysis
ALL_FLOW_FEATURES = KEY_REVIEW1_FEATURES + [
    "Total_Fwd_Packets",
    "Total_Bwd_Packets",
    "ACK_Flag_Count",
    "Flow_IAT_Mean",
    "Subflow_Fwd_Bytes",
    "Protocol"
]


def clean_flow_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sanitize flow dataframe by handling inf/-inf and missing values.
    Common in CIC-style datasets where Flow_Duration = 0 causes division by zero.
    """
    df_clean = df.copy()
    
    # Replace infinite values with NaN then impute or drop
    df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Fill remaining NaNs with column medians for numeric columns
    numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if df_clean[col].isnull().sum() > 0:
            median_val = df_clean[col].median()
            df_clean[col] = df_clean[col].fillna(median_val)
            
    return df_clean


def prepare_flow_data(
    csv_path: str,
    feature_cols: Optional[List[str]] = None,
    target_col: str = "Binary_Label",
    test_size: float = 0.20,
    random_state: int = 42,
    scale_features: bool = True,
    scaler_save_path: Optional[str] = None,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str], Optional[object]]:
    """
    Load raw flow data, extract features, perform train/test split, and optionally scale.

    Returns:
        X_train, X_test, y_train, y_test, feature_names, fitted_scaler
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Run data_generator.py first.")

    df = pd.read_csv(csv_path)
    df = clean_flow_dataframe(df)

    if feature_cols is None:
        feature_cols = [c for c in ALL_FLOW_FEATURES if c in df.columns]

    X = df[feature_cols].copy()
    y = df[target_col].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    scaler = None
    if scale_features:
        scaler = RobustScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        if scaler_save_path:
            os.makedirs(os.path.dirname(scaler_save_path), exist_ok=True)
            joblib.dump(scaler, scaler_save_path)
            
        return X_train_scaled, X_test_scaled, y_train, y_test, feature_cols, scaler

    return X_train.values, X_test.values, y_train, y_test, feature_cols, None


if __name__ == "__main__":
    csv = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "network_flows.csv")
    scaler_out = os.path.join(os.path.dirname(__file__), "..", "models", "scaler.joblib")
    X_train, X_test, y_train, y_test, features, _ = prepare_flow_data(
        csv_path=csv,
        feature_cols=ALL_FLOW_FEATURES,
        scaler_save_path=scaler_out
    )
    print(f"[Preprocessing] Data prepared successfully:")
    print(f"  - Features ({len(features)}): {features}")
    print(f"  - Train shape: {X_train.shape}, Test shape: {X_test.shape}")
    print(f"  - Target distribution (Train): Attack={sum(y_train)}, Benign={len(y_train)-sum(y_train)}")
