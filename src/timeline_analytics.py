"""
CYBERGUARD AI - Attack Timeline & Historical Traffic Analytics
Module 7: Temporal Traffic Analytics & Threat Surge Visualization

Provides time-series analytics of network traffic volume, protocol distribution,
and attack surge timelines formatted for dark SOC interfaces.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px


def build_traffic_timeline_chart(flow_records: List[Dict[str, Any]], height: int = 340) -> go.Figure:
    """
    Renders a time-series plot comparing Benign vs Attack packet rates over time.
    """
    if not flow_records:
        # Create a representative baseline timeline
        base_time = datetime.now() - timedelta(minutes=15)
        times = [base_time + timedelta(seconds=i*15) for i in range(40)]
        benign_pps = [np.random.normal(18, 4) for _ in range(40)]
        attack_pps = [0.0] * 20 + [np.random.normal(3200, 400) for _ in range(12)] + [0.0] * 8
        df_time = pd.DataFrame({
            "Time": [t.strftime("%H:%M:%S") for t in times],
            "Benign_PPS": [max(0.1, p) for p in benign_pps],
            "Attack_PPS": [max(0.0, p) for p in attack_pps]
        })
    else:
        df_raw = pd.DataFrame(flow_records)
        df_raw["Time"] = df_raw.get("Timestamp", [datetime.now().strftime("%H:%M:%S")] * len(df_raw))
        df_raw["PPS"] = df_raw.get("Packets_Sec", df_raw.get("Flow_Packets_Sec", 10.0)).astype(float)
        
        benign_rows = df_raw[df_raw["Verdict"] == "Benign"]
        attack_rows = df_raw[df_raw["Verdict"] == "Attack"]
        
        times = df_raw["Time"].unique().tolist()
        df_time = pd.DataFrame({
            "Time": times,
            "Benign_PPS": [benign_rows[benign_rows["Time"] == t]["PPS"].mean() if t in benign_rows["Time"].values else 0.0 for t in times],
            "Attack_PPS": [attack_rows[attack_rows["Time"] == t]["PPS"].mean() if t in attack_rows["Time"].values else 0.0 for t in times]
        })

    fig = go.Figure()
    
    # Benign stream trace
    fig.add_trace(go.Scatter(
        x=df_time["Time"],
        y=df_time["Benign_PPS"],
        mode="lines",
        name="Benign Traffic (pps)",
        line=dict(color="#78A995", width=2),
        fill="tozeroy",
        fillcolor="rgba(120, 169, 149, 0.08)"
    ))

    # Attack spike trace
    fig.add_trace(go.Scatter(
        x=df_time["Time"],
        y=df_time["Attack_PPS"],
        mode="lines+markers",
        name="DDoS Attack Flood (pps)",
        line=dict(color="#E36B62", width=2.5),
        marker=dict(size=5, color="#F0C75E"),
        fill="tozeroy",
        fillcolor="rgba(227, 107, 98, 0.15)"
    ))

    fig.update_layout(
        title=dict(
            text="<b>Real-Time Traffic Rate Timeline (Packets/sec)</b>",
            font=dict(family="Inter, sans-serif", size=13, color="#E5E7EB"),
            x=0.01, y=0.96
        ),
        paper_bgcolor="#1C222C",
        plot_bgcolor="#151A22",
        font=dict(family="Inter, sans-serif", color="#9CA3AF", size=11),
        margin=dict(l=45, r=20, t=45, b=35),
        height=height,
        legend=dict(
            bgcolor="rgba(28, 34, 44, 0.9)",
            bordercolor="#353B45",
            borderwidth=1,
            font=dict(color="#E5E7EB", size=10.5),
            x=0.02, y=0.95
        ),
        xaxis=dict(
            gridcolor="rgba(53, 59, 69, 0.45)",
            tickfont=dict(color="#9CA3AF", size=9.5),
            title_font=dict(color="#E5E7EB", size=10.5)
        ),
        yaxis=dict(
            title="Ingress Packet Rate (pps)",
            gridcolor="rgba(53, 59, 69, 0.45)",
            tickfont=dict(color="#9CA3AF", size=9.5),
            title_font=dict(color="#E5E7EB", size=10.5)
        )
    )
    return fig


def build_cumulative_mitigation_chart(flow_records: List[Dict[str, Any]], height: int = 240) -> go.Figure:
    """
    Renders cumulative attack mitigation count over time.
    """
    if not flow_records:
        x_vals = [f"T-{i}m" for i in range(10, 0, -1)]
        y_vals = [0, 1, 2, 4, 7, 12, 18, 25, 31, 38]
    else:
        attack_records = [f for f in flow_records if f.get("Verdict") == "Attack"]
        x_vals = [f.get("Timestamp", f"T{i}") for i, f in enumerate(attack_records)]
        y_vals = list(range(1, len(x_vals) + 1))

    fig = go.Figure(go.Scatter(
        x=x_vals,
        y=y_vals,
        mode="lines+markers",
        name="Cumulative Threat Blocks",
        line=dict(color="#D6B85A", width=2.5),
        marker=dict(color="#F0C75E", size=6)
    ))

    fig.update_layout(
        title=dict(
            text="<b>Cumulative Threat Interceptions</b>",
            font=dict(family="Inter, sans-serif", size=12.5, color="#E5E7EB"),
            x=0.01, y=0.96
        ),
        paper_bgcolor="#1C222C",
        plot_bgcolor="#151A22",
        font=dict(family="Inter, sans-serif", color="#9CA3AF", size=10.5),
        margin=dict(l=40, r=20, t=40, b=30),
        height=height,
        xaxis=dict(gridcolor="rgba(53, 59, 69, 0.45)", tickfont=dict(color="#9CA3AF", size=9)),
        yaxis=dict(gridcolor="rgba(53, 59, 69, 0.45)", tickfont=dict(color="#9CA3AF", size=9))
    )
    return fig
