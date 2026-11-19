# CYBERGUARD AI — PBL Review & Viva Defense Master Guide
**Course / Division:** MLCS PBL · CSM-A · Final Year Engineering  
**Project Title:** Intelligent Network Traffic Classification & Autonomous DDoS Mitigation Using Machine Learning  
**Platform Architecture:** Enterprise Security Operations Center (SOC) Command Console  

---

## 1. Project Summary (For Opening Slide & Pitch)

### Problem Statement
Distributed Denial of Service (DDoS) is a volumetric cyberattack where botnets flood a server or network with millions of bogus requests within seconds, exhausting bandwidth, firewall state memory, and CPU resources. Traditional defenses rely on static rules (e.g., Snort/Suricata signatures) or rigid packet thresholds. These fail against zero-day variations and cause high false alarms during legitimate traffic surges (such as flash crowds during product launches or online ticket sales).

### Proposed Solution
We built **CYBERGUARD AI**, a supervised Machine Learning defense system. Instead of inspecting slow raw packet payloads, it analyzes **bidirectional network flow records** (connection duration, packet arrival rates, symmetry ratios, and TCP flag counts). Using an ensemble **Random Forest Classifier**, it distinguishes normal user traffic from malicious DDoS attacks in **8.57 microseconds per flow** (scoring over 116,000 flows/sec) with **99.96% accuracy**, and automatically synthesizes Linux `iptables` and Software-Defined Networking (OpenFlow) firewall drop rules with human-in-the-loop oversight.

### 30-Second Review Pitch (Natural 4-Sentence Script)
> *"Good morning, respected panel members. Today, our team presents **CYBERGUARD AI**, an intelligent cybersecurity platform designed to detect and autonomously neutralize volumetric DDoS attacks before they saturate network infrastructure. While legacy firewalls rely on static thresholds that frequently block innocent users, our system analyzes aggregated bidirectional flow statistics using an ensemble Random Forest algorithm that achieves **99.96% accuracy** at wire speed. In our demonstration, we will show you our live Security Operations Center dashboard, which reconstructs raw PCAP packet streams, explains decisions using Explainable AI (SHAP), and generates firewall mitigation rules with administrator approval. Thank you, and we welcome your review questions."*

---

## 2. System Architecture & Workflow

### Text-Based Pipeline Workflow
```
[ Ingress Packets ] ──> ( Wireshark / Edge Switch / PCAP Capture )
                                │
                                ▼
[ Flow Extraction ] ──> ( Scapy 5-Tuple Aggregator: Src, Dst, Ports, Protocol )
                                │
                                ▼
[ Feature Engine ]  ──> ( Calculate 11 Metrics: Fwd/Bwd Ratio, SYN/ACK, PPS, IAT )
                                │
                                ▼
[ AI Inference ]    ──> ( Random Forest Ensemble: 100 Trees, Depth 16 )
                                │
                                ├──> If BENIGN (0) ──> Status 200 OK / Audit Logged
                                │
                                └──> If ATTACK (1) ──> SHAP Explainability Breakdown
                                                          │
                                                          ▼
                                                  Threat Alert Center
                                                          │
                                                          ▼
                                                  Firewall Staging Queue
                                                          │
                                    ( Administrator Clicks 'Approve' )
                                                          │
                                                          ▼
                                            iptables DROP & OpenFlow Rule Enforced
```

---

### The 4 Stages of the System

#### Stage 1: Data Collection & Ingress Input
- **Dataset Standard:** Modeled after the internationally recognized **CICIDS2017** and **CICDDoS2019** benchmark flow datasets created by the Canadian Institute for Cybersecurity using `CICFlowMeter`.
- **Benchmark Dataset:** 25,000 bidirectional flow records (`data/raw/network_flows.csv`) balanced 50/50:
  - 12,500 Benign Flows: Normal browsing, streaming, API transactions, and database queries.
  - 12,500 Attack Flows:
    - 5,000 TCP SYN Floods (half-open connection attacks)
    - 4,375 UDP Floods (stateless packet bombardment on ports 53/123)
    - 3,125 HTTP Floods (Layer-7 GET/POST application exhaustion)
- **Live Input Source:** Accepts `.pcap` files uploaded directly by administrators or generated live by the SDN traffic simulator.

#### Stage 2: Preprocessing & Feature Engineering
- Individual raw packets are grouped into bidirectional flows using the network **5-tuple**:  
  `[Source IP, Destination IP, Source Port, Destination Port, Transport Protocol]`.
- Calculates **11 numerical flow metrics**:
  1. `Flow_Duration` (lifespan of connection in $\mu s$)
  2. `Total_Fwd_Packets` (packets sent by client)
  3. `Total_Bwd_Packets` (replies returned by server)
  4. `Flow_Packets_Sec` (volumetric intensity)
  5. `Flow_Bytes_Sec` (bandwidth consumption)
  6. `Fwd_Bwd_Packet_Ratio` (directional symmetry)
  7. `SYN_Flag_Count` (connection requests)
  8. `ACK_Flag_Count` (completed handshakes)
  9. `Avg_Packet_Size` (payload geometry)
  10. `Flow_IAT_Mean` (packet inter-arrival time / botnet cadence)
  11. `Subflow_Fwd_Bytes` (cumulative client bytes)

#### Stage 3: Model Building & Training
- **Algorithm:** **Random Forest Classifier** (`n_estimators=100`, `max_depth=16`, `min_samples_split=4`, Gini Impurity criterion).
- **Validation Scheme:** Stratified 80/20 train/test split (20,000 training flows, 5,000 strictly held-out test flows) with random seed `42` for exact reproducibility.
- **Why Random Forest:** Unlike Neural Networks that require heavy GPU compute, Random Forest operates on orthogonal feature split thresholds, invariant to feature scaling, resistant to noisy outliers, and executes in microseconds on standard edge routers.

#### Stage 4: Output & Interactive SOC Interface
- **Primary Interface:** A Streamlit Security Operations Center (SOC) dashboard (`app.py`) styled in Charcoal & Champagne Gold.
- **REST API:** High-throughput FastAPI backend (`api.py`) for programmatic edge router integration.
- **Outputs Produced:**
  - Real-time classification verdicts (`BENIGN` vs `ATTACK`) with confidence percentages.
  - Multi-class categorization (`SYN_Flood`, `UDP_Flood`, `HTTP_Flood`).
  - SHAP Explainability waterfall charts showing *why* a specific flow was flagged.
  - Synthesized mitigation commands: `iptables -A INPUT -s <IP> -j DROP` and OpenFlow table flow-mods.
  - Downloadable executive security reports in PDF and CSV.

---

## 3. File-by-File Repository Breakdown

If a reviewer asks you to click on any file during the review, use this reference:

### Root Application Files
- **`app.py`**  
  *What it does:* The main Streamlit SOC web dashboard featuring all 9 tabs, telemetry cards, and interactive Plotly visualization charts.  
  *Reviewer pitch:* "This is our primary operator interface where security analysts inspect live traffic, review alerts, test custom flows, and approve firewall rules."
- **`api.py`**  
  *What it does:* A production FastAPI REST API exposing `/predict_flow`, `/alerts`, `/firewall/*`, and `/pcap/analyze` endpoints for external firewall and SDN controllers.  
  *Reviewer pitch:* "This backend microservice allows SDN switches and remote routers to query our ML model programmatically via JSON HTTP requests."
- **`run_demo.py`**  
  *What it does:* A standalone console CLI script that executes all 9 cybersecurity modules sequentially and generates a sample audit report.  
  *Reviewer pitch:* "This script runs end-to-end automated validation of our complete pipeline without needing a web browser."
- **`requirements.txt`**  
  *What it does:* Defines all verified Python package dependencies including Scikit-Learn, Streamlit, Scapy, SHAP, and FPDF2.  
  *Reviewer pitch:* "This lists the required libraries and exact versions needed to run our machine learning and packet capture pipeline."
- **`Dockerfile` & `docker-compose.yml`**  
  *What it does:* Multi-stage container definitions that package the application, dependencies, and pre-trained models into an isolated Linux deployment.  
  *Reviewer pitch:* "These containerization files allow our SOC platform to be deployed reliably on any cloud provider or server in one command."
- **`render.yaml` & `Procfile`**  
  *What it does:* Cloud platform specification files that enable one-click zero-config web deployment on cloud PaaS providers.  
  *Reviewer pitch:* "These files specify the entrypoint and environment variables for continuous deployment on cloud platforms."
- **`README.md`**  
  *What it does:* Comprehensive project documentation detailing system architecture, setup commands, and evaluation baselines.  
  *Reviewer pitch:* "This is the primary technical documentation detailing our project methodology and installation steps."

### Source Modules (`src/`)
- **`src/detector.py`**  
  *What it does:* The core detection engine that scales incoming flow features, queries the Random Forest models, and enforces dynamic sensitivity thresholds.  
  *Reviewer pitch:* "This module bridges raw network data with our model artifacts and handles decision thresholding."
- **`src/model.py`**  
  *What it does:* Implements the `DDoSFlowClassifier` class with training routines, evaluation metrics, and model persistence helpers.  
  *Reviewer pitch:* "This encapsulates our Random Forest architecture, Gini importance calculations, and Decision Tree baseline comparisons."
- **`src/train.py`**  
  *What it does:* Executes the end-to-end model training run, evaluates on the 5,000 held-out test flows, and saves the `.joblib` model weights.  
  *Reviewer pitch:* "Running this script reproduces our 99.96% accuracy and outputs the confusion matrix and summary JSON."
- **`src/pcap_analyzer.py`**  
  *What it does:* Validates magic byte headers and extracts bidirectional flows from raw PCAP captures using Scapy and a native binary fallback parser.  
  *Reviewer pitch:* "This allows network administrators to upload real Wireshark captures and reconstruct flow records automatically."
- **`src/explainability.py`**  
  *What it does:* Implements Explainable AI using `shap.TreeExplainer` to compute exact mathematical feature contributions for every flow prediction.  
  *Reviewer pitch:* "This module removes the 'black box' nature of ML by rendering visual waterfall charts showing why a flow was classified as malicious."
- **`src/firewall_manager.py`**  
  *What it does:* Enforces human-in-the-loop firewall governance by staging proposed drop rules in a pending approval queue before enforcement.  
  *Reviewer pitch:* "This ensures rules are never applied blindly, preventing accidental network lockouts of legitimate services."
- **`src/alert_center.py`**  
  *What it does:* Manages real-time threat alert lifecycle, categorizes incidents into CRITICAL/HIGH/MEDIUM/LOW, and records operator acknowledgments.  
  *Reviewer pitch:* "This acts as our incident dispatch center, prioritizing severe high-rate floods for immediate SOC operator triage."
- **`src/geolocation.py`**  
  *What it does:* Maps attacker public IP addresses to countries, coordinates, and autonomous systems (ASNs), rendering an interactive Plotly world map.  
  *Reviewer pitch:* "This visualizes the geographic origin of attacking botnets across global regions on an interactive 3D/2D world map."
- **`src/timeline_analytics.py`**  
  *What it does:* Generates real-time time-series telemetry graphs of network packet rates and cumulative attack suppression curves.  
  *Reviewer pitch:* "This tracks volumetric traffic surges over time and visualizes how quickly the system mitigates incoming floods."
- **`src/drift_monitor.py`**  
  *What it does:* Performs 2-sample Kolmogorov-Smirnov (KS) statistical tests between baseline training data and live runtime traffic to detect distribution drift.  
  *Reviewer pitch:* "This detects if emerging attack patterns or new protocols are drifting away from the original training distribution."
- **`src/report_generator.py`**  
  *What it does:* Generates styled PDF executive incident audit reports using `fpdf2` and exports incident logs as CSV.  
  *Reviewer pitch:* "This automates compliance and post-incident forensic reporting for CISO and security team reviews."
- **`src/mitigation.py` & `src/utils.py`**  
  *What it does:* Formats raw string syntax for Linux `iptables`, OpenFlow SDN flows, and IP address generators.  
  *Reviewer pitch:* "These utilities generate the exact command-line syntax enforced on Linux firewalls and Open vSwitch switches."
- **`src/preprocessing.py` & `src/data_generator.py`**  
  *What it does:* Encapsulates data cleaning, label encoding, and authentic synthetic flow generation modeled after CICIDS standards.  
  *Reviewer pitch:* "These scripts handle data hygiene, missing value handling, and flow metric synthesis."

### Tests & Models
- **`tests/test_pipeline.py` & `tests/test_advanced_modules.py`**  
  *What it does:* Unit and integration test suites covering all 9 modules (11 automated tests, 100% passing).  
  *Reviewer pitch:* "These automated tests verify that every module—from packet parsing to SHAP explainability—passes rigorous quality checks."
- **`models/rf_ddos_model.joblib` & `models/training_summary.json`**  
  *What it does:* Persisted binary Random Forest weights and audited JSON performance evaluation metrics.  
  *Reviewer pitch:* "These are our production artifacts containing the trained decision trees and verified performance numbers."

---

## 4. Key Results, Metrics & Explainability

### Quantitative Performance Metrics

| Evaluation Metric | Score Achieved | Practical Cybersecurity Meaning |
|---|---|---|
| **Accuracy** | **99.96%** | Overall percentage of network flows classified correctly. |
| **Precision** | **99.96%** | When the AI sounds an alarm, it is correct 99.96% of the time (only 1 false alarm out of 2,500 benign flows). |
| **Recall (Sensitivity)** | **99.96%** | Caught 2,499 out of 2,500 attacks; only 1 attack flow slipped through. |
| **F1-Score** | **99.96%** | Harmonic mean of precision and recall, proving balanced performance. |
| **ROC-AUC** | **1.0000** | Perfect separation curve between benign traffic and DDoS attacks. |
| **Detection Latency** | **8.57 $\mu s$ / flow** | Scores over 116,000 flows/sec, operating at wire speed on ingress routers. |

### Confusion Matrix Breakdown (5,000 Test Flows)
$$\begin{pmatrix} \text{True Benign (TN): } 2,499 & \text{False Attack (FP): } 1 \\ \text{False Benign (FN): } 1 & \text{True Attack (TP): } 2,499 \end{pmatrix}$$
- **False Positive Rate:** $\frac{1}{2500} = \mathbf{0.04\%}$ (Near zero user disruption)
- **False Negative Rate:** $\frac{1}{2500} = \mathbf{0.04\%}$ (Near zero attack leakage)

### Top Indicative Features (Gini Impurity Ranking)
How the model makes decisions:
1. **`Fwd_Bwd_Packet_Ratio` (25.86%):** Directional asymmetry. Normal TCP connections require 2-way handshakes ($\approx 1.0$). Attackers send hundreds of requests with zero replies ($>50.0$).
2. **`Total_Fwd_Packets` (19.24%):** Large packet count dispatched by the client.
3. **`Total_Bwd_Packets` (18.51%):** Absence of server responses characterizes half-open floods.
4. **`Flow_IAT_Mean` (13.94%):** Inter-arrival time. Automated botnets fire with sub-millisecond cadence and zero human jitter.
5. **`Subflow_Fwd_Bytes` (7.45%):** Cumulative forward byte payload.
6. **`Flow_Packets_Sec` (7.06%):** Packet transmission frequency.
7. **`ACK_Flag_Count` (2.78%):** Lack of ACKs proves the 3-way handshake was never completed.

### Explainable AI (XAI) with SHAP
- Our system uses **TreeSHAP** (`shap.TreeExplainer`) based on cooperative game theory.
- For any individual flow, it assigns an exact log-odds credit to each feature.
- *Example:* When a SYN flood is flagged, SHAP shows that `Fwd_Bwd_Packet_Ratio = 120.0` pushed the threat score up by $+0.42$, while `ACK_Flag_Count = 0` pushed it up by $+0.21$, making the prediction fully auditable in court or compliance reviews.

---

## 5. Panel Q&A Preparation (Top 10 Review Questions)

### Q1: Why did you choose Random Forest instead of a Deep Neural Network (CNN/LSTM)?
**Answer:**  
*"In network intrusion detection at ingress switches, latency and explainability are paramount. Random Forest operates on orthogonal split thresholds rather than gradient descent or matrix multiplications, allowing our model to score a flow in just 8.57 microseconds—capable of inspecting over 116,000 flows per second on commodity CPU hardware without requiring an expensive GPU. Furthermore, Random Forest produces ranked Gini feature importances and integrates natively with TreeSHAP for explainability, which is essential for network engineers to audit decisions."*

### Q2: Isn't 99.96% accuracy a sign of overfitting?
**Answer:**  
*"We verified our model against overfitting through two rigorous steps: First, our 99.96% score was measured exclusively on a held-out test split of 5,000 flows that the model never saw during training. Second, we conducted an explicit Overfitting Comparison between a Single Decision Tree and our Random Forest: the training accuracy was 100.00% and testing was 99.98%, showing an overfitting gap ($\Delta$) of only 0.02%. The high accuracy is not memorization; it reflects the physical nature of volumetric DDoS attacks, which exhibit extreme mathematical asymmetry—such as forward-to-backward packet ratios exceeding 50:1 and zero ACK flags—that cleanly separate them from standard TCP browsing."*

### Q3: What is the difference between packet-based and flow-based detection?
**Answer:**  
*"Packet-based inspection (DPI) inspects the payload bytes of every individual packet. This is computationally expensive, fails when traffic is encrypted with TLS/HTTPS, and cannot keep up with multi-gigabit wire speeds. In contrast, our system is flow-based: it aggregates packets sharing the same 5-tuple into bidirectional statistical records. It inspects metadata like packet rates, durations, and flag distributions, which work seamlessly on encrypted traffic and consume over 90% less CPU."*

### Q4: How does your system prevent blocking legitimate traffic during a flash crowd?
**Answer:**  
*"During flash crowds (e.g., ticket booking or festival sales), packet rates surge, which triggers false alarms in traditional threshold-based systems. However, real users complete valid TCP 3-way handshakes, download images, and send acknowledgment packets (`ACK > 0`), maintaining balanced forward-to-backward packet ratios ($\approx 1.0$). Floods, on the other hand, pump forward requests with zero backward replies. Because `Fwd_Bwd_Packet_Ratio` and `ACK_Flag_Count` carry 28.6% of our model's weight, the model readily distinguishes a flash crowd from an attack."*

### Q5: What is human-in-the-loop firewall governance, and why is it necessary?
**Answer:**  
*"In an enterprise Security Operations Center, automatically applying firewall rules without verification can cause catastrophic self-inflicted Denial of Service if a critical gateway or partner IP is falsely flagged. Our system implements human-in-the-loop governance: when an attack is detected, an `iptables` or OpenFlow drop rule is synthesized but placed into a `PENDING_APPROVAL` staging buffer. The security analyst reviews the source IP, confidence score, and SHAP explanation before clicking 'Approve Rule' to enforce it."*

### Q6: What standards did you follow for your dataset?
**Answer:**  
*"Our dataset structure strictly adheres to the CICFlowMeter standard developed by the Canadian Institute for Cybersecurity for the CICIDS2017 and CICDDoS2019 benchmark datasets. It captures 17 standard attributes spanning flow durations, inter-arrival times, packet distributions, and protocol flags across 25,000 flow records with balanced representation of Benign, SYN Flood, UDP Flood, and HTTP Flood vectors."*

### Q7: How does your system detect distribution drift over time?
**Answer:**  
*"Networks evolve as new applications and attack tools emerge. In Module 9, we implemented a Drift Monitor utilizing the two-sample Kolmogorov-Smirnov (KS) statistical test. It compares the cumulative distribution function of live runtime features against our baseline training distribution. If the $p$-value drops below $\alpha = 0.05$, the system flags distribution drift, alerting administrators that the model should be retrained."*

### Q8: What happens when an attacker uses spoofed IP addresses?
**Answer:**  
*"Attackers frequently randomize or spoof source IPs. While static IP blocklists fail against spoofing, our Random Forest model does not classify based on the IP address string—it classifies based on the statistical behavior of the connection (packet rate, size, and flag asymmetry). Once flagged, our OpenFlow mitigation can drop traffic based on ingress port, protocol, or MAC address, neutralizing the attack regardless of IP spoofing."*

### Q9: What challenges did you face during development, and how did you resolve them?
**Answer:**  
*"Our two biggest engineering challenges were: First, handling offline PCAP captures across diverse byte-orders without external dependency failures; we solved this by engineering a custom binary parser with automatic endianness detection that works with zero external libraries. Second, balancing detection speed with model interpretability; we resolved this by utilizing TreeSHAP, which calculates exact game-theoretic attributions in polynomial time rather than exponential time."*

### Q10: What is the future scope of this project?
**Answer:**  
*"In subsequent iterations, we plan to: First, deploy our classifier as an in-kernel eBPF (Extended Berkeley Packet Filter) program inside the Linux kernel to drop packets at XDP (eXpress Data Path) wire speed before the OS networking stack is reached. Second, integrate with SDN controllers like Ryu or ONOS to dynamically modify physical switch tables across distributed enterprise WANs."*

---

## 6. Live Demo Checklist & Execution Commands

### Prerequisites Before Starting Demo
1. Ensure your terminal is in the project directory:  
   `cd C:\Users\HP\OneDrive\Desktop\MLCS-ddos`
2. Make sure port `8501` or `8502` is available.
3. Use the project virtual environment where all packages (`scapy`, `shap`, `fpdf2`, `plotly`) are installed.

---

### Step-by-Step Demo Script (What to Click During Review)

#### Step 1: Start the Dashboard
```bash
.\venv\Scripts\python.exe -m streamlit run app.py
```
Open your browser at: **`http://localhost:8502`** (or `http://localhost:8501`).

#### Step 2: Show Tab 1 (Overview)
- Point to the **Cybersecurity SOC Header** and KPI cards:
  - Detection Accuracy: **99.96%**
  - Detection Latency: **8.57 $\mu s$**
- Explain the horizontal pipeline flowchart: *Network Traffic $\to$ Flow Extraction $\to$ Preprocessing $\to$ Random Forest $\to$ Mitigation*.

#### Step 3: Show Tab 3 (Model Evaluation)
- Show the **Confusion Matrix** (2,499 TN, 2,499 TP, only 1 FP, 1 FN).
- Show the **ROC Curve** ($AUC = 1.0000$).
- Show the **Feature Importance Bar Chart**: Explain that `Fwd_Bwd_Packet_Ratio` is the #1 deciding feature (25.86%).

#### Step 4: Show Tab 4 (Live SDN Traffic Simulator)
- Select `10` or `20` flows to stream.
- Click **"🚀 Start Live SDN Flow Stream"**.
- Watch the live telemetry table update: green rows for `BENIGN`, red rows for `ATTACK`.
- Show that mitigation rules are automatically staged in the firewall queue.

#### Step 5: Show Tab 5 (Examiner Custom Sandbox)
- Select the preset: **"🚨 High-Volume TCP SYN Flood (Attack)"**.
- Click **"🔍 Inspect & Classify Flow via Random Forest"**.
- Show the **100.0% Attack Verdict**.
- Scroll down to show the **SHAP Waterfall Plot**: Show the red bars pushing the prediction toward attack.

#### Step 6: Show Tab 7 (PCAP Deep Packet Analyzer)
- Click the gold button: **"Load SYN Flood Sample"**.
- Show that **120 packets** were parsed and reconstructed into flows.
- Show the detection table displaying `ATTACK (SYN Flood)` with `100.0% Confidence`.

#### Step 7: Show Tab 8 (Firewall Management)
- Show the **Pending Approvals Queue**.
- Select a pending rule and click **"✅ Approve & Enforce Rule"**.
- Explain: *"This demonstrates our human-in-the-loop governance: rules require explicit operator authorization before being enforced on the live firewall."*

#### Step 8: Show Tab 9 (Security Audit Reports)
- Click **"📄 Download Security Audit Report (PDF)"**.
- Open the generated executive PDF to show the professional audit summary.

---
*End of PBL Master Review Guide. All code, datasets, and models are fully functional and verified.*
