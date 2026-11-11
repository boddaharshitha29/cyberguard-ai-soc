# CYBERGUARD AI — Advanced AI-Powered Cybersecurity Monitoring Platform
### MLCS Project-Based Learning (PBL) · Final Year Engineering Project · CSM-A
### Enterprise Security Operations Center (SOC) Defense System

> **Real-time Distributed Denial-of-Service (DDoS) detection, TreeSHAP Explainable AI, live PCAP traffic analysis, attack geolocation, and human-in-the-loop firewall mitigation.**

---

## 🛡️ Executive System Overview
**CYBERGUARD AI** transforms traditional network intrusion detection into an enterprise-grade Security Operations Center (SOC) defense console. Powered by supervised **Random Forest Ensemble Learning**, the system classifies high-dimensional network flow records in **8.57 microseconds** with **99.96% accuracy** and provides actionable forensic explainability.

### 🎨 SOC Design Palette
- **Main Background:** `#11151D` (Deep Charcoal)
- **Sidebar Background:** `#0D1118` (Midnight Navy)
- **Card Background:** `#1C222C` (Elevated Glassmorphism)
- **Secondary Card Background:** `#252C36` (Border Panels & Badges)
- **Primary Accent:** `#D6B85A` (Champagne Gold)
- **Gold Highlight:** `#F0C75E` (Warm Metric Gold)
- **Success Status:** `#78A995` (Benign Sage Green)
- **Danger Status:** `#E36B62` (Attack Coral Red)
- **Warning Status:** `#E5A94B` (Amber Alert)
- **Borders & Dividers:** `#353B45`

---

## ⚡ 9 Advanced AI & SOC Modules

| Module | Core Capability | Implementation Details |
| :--- | :--- | :--- |
| **1. Threat Alert Center** | Real-time incident queue & triage | Classifies alerts into `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` with operator acknowledgment and alert lifecycle retention. |
| **2. Explainable AI (SHAP)** | Local flow attribution & XAI | Employs `shap.TreeExplainer` on Random Forest decision trees to quantify exact feature attributions ($\phi_i$) pushing verdicts towards Attack vs. Benign. |
| **3. PCAP Traffic Analyzer** | Raw packet capture ingestion | Safely validates PCAP/PCAPNG magic headers (<=25MB), parses packets via Scapy, reconstructs bidirectional 5-tuple flows, and evaluates threat vectors. |
| **4. Attack Geolocation Map** | Global threat origin visualizer | Resolves external source IPs to geographic coordinates, cities, and autonomous systems (ASNs), rendering an interactive Plotly world threat map. |
| **5. Firewall Management** | Human-in-the-loop mitigation | **No automatic execution without operator authorization.** Features Pending Approval Queue, Active Enforced Blocks, Protected Whitelist, and Bash script export. |
| **6. Security Report Generator** | Executive audit compliance | Generates branded executive PDF audit reports via `fpdf2` and exports full forensic flow logs to CSV. |
| **7. Attack Timeline Analytics** | Time-series traffic surge metrics | Interactive time-series tracking packet rates (pps), bandwidth throughput, protocol trends, and cumulative blocked threats over time. |
| **8. Threshold Configuration** | Sensitivity & trade-off tuning | Dynamic slider allowing operators to adjust the classification probability threshold $\theta \in [0.10, 0.90]$ to optimize Precision vs. Recall. |
| **9. Model Drift Monitoring** | Data stability & OOD detection | Evaluates 2-sample Kolmogorov-Smirnov statistical tests between live traffic and baseline training distributions to flag zero-day traffic shifts. |

---

## 🔄 End-to-End System Architecture

```
[ 1. Ingress Network Traffic ] ──► [ 2. Flow Reconstruction ] ──► [ 3. Feature Sanitization ]
   • Router / SDN Switch Capture      • 5-tuple aggregation              • Inf/NaN imputation
   • Live PCAP File Upload            • Duration, rates, flag counts      • Robust rate scaling
                                                                                   │
                                                                                   ▼
[ 6. Automated Mitigation ]   ◄── [ 5. Operator Governance ]  ◄── [ 4. RF Ensemble & XAI ]
   • Linux Kernel iptables            • Human-in-the-Loop Approval        • 100-tree classification
   • Open vSwitch OpenFlow            • Protected IP Whitelisting         • SHAP feature attribution
   • Real-Time Threat Alerts          • Audited Execution Logging         • Multi-class vector (SYN/UDP/HTTP)
```

---

## 📊 Evaluation & Verification Benchmarks (Held-out Test Split)

| Evaluation Metric | Score Achieved | Industry Benchmark Standard |
| :--- | :--- | :--- |
| **Classification Accuracy** | **99.96%** | High-precision flow classification |
| **Precision Score** | **99.96%** | $0.04\%$ false alarm rate on critical servers |
| **Recall (Sensitivity)** | **99.96%** | Catches $99.96\%$ of active volumetric attacks |
| **F1-Score** | **99.96%** | Balanced harmonic class mean |
| **ROC-AUC** | **1.0000** | Perfect separation boundary |
| **Detection Latency** | **8.57 $\mu s$ / flow** | Ultra-low latency (> 116,000 flows/sec throughput) |
| **Multi-Class Accuracy** | **99.98%** | Discretizes SYN Floods, UDP Floods, and HTTP Floods |

---

## 📂 Project Directory Structure

```
MLCS-ddos/
├── data/
│   ├── raw/
│   │   └── network_flows.csv          # 25,000 benchmark flow records (CICIDS/CICDDoS standard)
│   └── sample_pcaps/
│       ├── syn_flood_sample.pcap      # Pre-packaged SYN flood packet capture
│       ├── udp_flood_sample.pcap      # Pre-packaged UDP amplification packet capture
│       └── benign_traffic_sample.pcap # Pre-packaged legitimate HTTP browsing capture
├── models/
│   ├── rf_ddos_model.joblib           # Trained binary Random Forest ensemble
│   ├── rf_multiclass_model.joblib     # Trained multi-class attack classifier
│   ├── scaler.joblib                  # Robust feature scaler
│   └── training_summary.json          # Metrics, confusion matrix, and feature importances
├── src/
│   ├── __init__.py
│   ├── data_generator.py              # Synthetic flow dataset generator
│   ├── preprocessing.py               # Preprocessing and train/test splitting
│   ├── model.py                       # Random Forest model & overfitting comparison
│   ├── train.py                       # Training pipeline runner
│   ├── detector.py                    # Real-time scoring engine with thresholding
│   ├── utils.py                       # IP generators and firewall rule synthesizers
│   ├── alert_center.py                # Module 1: Threat alert center with severity triage
│   ├── explainability.py              # Module 2: SHAP TreeExplainer feature attribution
│   ├── pcap_analyzer.py               # Module 3: PCAP validator, flow reconstructor & tester
│   ├── geolocation.py                 # Module 4: IP Geolocation mapping & Plotly globe
│   ├── firewall_manager.py            # Module 5: Firewall approval queue, blocklist, whitelist
│   ├── report_generator.py            # Module 6: Executive PDF & CSV audit reports (fpdf2)
│   ├── timeline_analytics.py          # Module 7: Historical traffic analytics & attack timeline
│   └── drift_monitor.py               # Modules 8 & 9: Detection threshold & Model drift monitor
├── tests/
│   ├── __init__.py
│   ├── test_pipeline.py               # Base model & pipeline test suite
│   └── test_advanced_modules.py       # Full test suite covering all 9 advanced modules
├── app.py                             # Streamlit SOC dashboard application
├── api.py                             # FastAPI REST endpoint with full module endpoints
├── run_demo.py                        # Comprehensive end-to-end CLI demonstration runner
├── requirements.txt                   # Project dependencies
└── README.md                          # Platform documentation
```

---

## 🚀 Execution & Demonstration Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the End-to-End CLI Demonstration
Executes model loading, flow inspection, SHAP explainability, geolocation, firewall staging/approval, PCAP reconstruction, and PDF generation:
```bash
python run_demo.py
```

### 3. Launch the Interactive SOC Dashboard (Streamlit)
```bash
python -m streamlit run app.py
```
👉 Open browser at: **`http://localhost:8501/`**

**Navigation Console:**
* **📌 TAB 1: Overview:** Mission statement, 6-stage architecture, KPI cards, timeline, and global geolocation map.
* **📊 TAB 2: EDA & Data Analysis:** Flow volume distributions, protocol charts, box plots, and correlation matrix.
* **🎯 TAB 3: Model Evaluation:** Confusion matrix, ROC curve, feature importance, overfitting analysis, and threshold trade-off curve.
* **⚡ TAB 4: Live SDN Traffic Simulator:** Controls to stream flows, inspect live packets, and stage rules for approval.
* **🧪 TAB 5: Examiner Custom Flow Sandbox:** Interactive feature sliders, **TreeSHAP local attribution plot**, and forensic insights.
* **🚨 TAB 6: Threat Alert Center:** Filter alerts by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and acknowledge incidents.
* **📦 TAB 7: PCAP Traffic Analyzer:** Upload external captures or load pre-packaged samples (`syn_flood_sample.pcap`, etc.).
* **🛡️ TAB 8: Firewall Management:** **Pending Approval Queue**, Active Enforced Blocklist, Protected Whitelist, and Bash script export.
* **📑 TAB 9: Security Audit Reports:** One-click download of the **Executive PDF Audit Report** and **Flow Logs CSV**.

### 4. Launch the REST API
```bash
uvicorn api:app --reload --port 8000
```
* **Swagger API Documentation:** `http://localhost:8000/docs`
* **Score Flow:** `POST /predict_flow`
* **Query Alerts:** `GET /alerts`
* **Approve Firewall Rule:** `POST /firewall/approve/{rule_id}`
* **Upload PCAP:** `POST /pcap/analyze`
* **Export Firewall Bash Script:** `GET /firewall/export_bash`

### 5. Run Automated Test Suite
```bash
python -m pytest tests/ -v
```
*(All 11 tests covering unit, pipeline, and advanced modules pass seamlessly).*

---

## 🔒 Security & Governance Notice
All firewall mitigation actions in CYBERGUARD AI adhere to the principle of least privilege and strict human-in-the-loop verification. No external network modifications are applied without operator authorization.
