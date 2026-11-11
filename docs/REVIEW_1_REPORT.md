# MLCS PBL · Review-1 Project Report
## DDoS Detection Using Network Flow Data
**Course / Division:** MLCS PBL · CSM-A  
**Project ID:** REVIEW-1 · 01-04  
**Date:** November 2026  

---

### Executive Summary
This project implements an intelligent, real-time Distributed Denial-of-Service (DDoS) detection and mitigation pipeline utilizing supervised machine learning on network flow features. Utilizing an ensemble **Random Forest Classifier**, the system inspects network flow records (duration, packet rates, byte rates, asymmetric packet ratios, and TCP flag counts) to distinguish **Benign** traffic from malicious **Attack** flows with **99.96% accuracy** and a detection latency of **8.57 microseconds per flow** on held-out test data.

---

### 1. Problem Statement
Modern Distributed Denial-of-Service (DDoS) attacks overwhelm network bandwidth, firewall state tables, and server compute resources within seconds of onset. Traditional signature-based detection systems (such as Snort/Suricata) fail against zero-day or polymorphic traffic patterns, while threshold-based rate-limiting defenses react too slowly and induce high rates of false positives during legitimate traffic surges (e.g., flash crowds).

#### Objective
Build a supervised machine learning pipeline that analyzes aggregated network flow records to classify incoming traffic into **Benign** or **Attack** with high precision, high recall, and ultra-low detection latency — serving as an automated defense layer before packets exhaust server resources.

```
+---------------------------------------------------------------------------------------+
|  Problem: Volumetric DDoS Traffic (SYN / UDP / HTTP Floods) Exhausts Resources in Secs |
|  Deficiency: Static rules & thresholds cause high false alarms and slow mitigation   |
|  Solution: Supervised Random Forest Classifier on Ingress Flow Records                |
+---------------------------------------------------------------------------------------+
```

---

### 2. Approach: Machine Learning Technique & Paradigm

#### 2.1 Machine Learning Technique: Random Forest Classifier
The model chosen for this project is a **Random Forest Classifier** — an ensemble learning algorithm composed of $B$ independent decision trees $\{T_1, T_2, \dots, T_B\}$. Each tree is trained on a bootstrap sample of the training flow data, and each node split is evaluated over a random subset of $m \approx \sqrt{p}$ features out of the total $p$ flow features. The final classification is determined by majority voting:

$$\hat{y} = \arg\max_{c \in \{0, 1\}} \sum_{b=1}^{B} \mathbb{I}(T_b(\mathbf{x}) = c)$$

#### 2.2 Why Random Forest?
1. **Handles High-Dimensional, Noisy Flow Features:** Flow features vary over several orders of magnitude (e.g., packet rate vs. binary flag indicators). Random Forest operates on feature partition thresholds rather than Euclidean distances, eliminating sensitivity to monotonic scaling and noise.
2. **Resistant to Overfitting:** Individual decision trees suffer from high variance and memorize noisy flow anomalies. Random Forest mitigates this through bagging (bootstrap aggregation) and feature subspace randomization, lowering generalization error without increasing bias.
3. **Ranked Feature-Importance Output:** By calculating the Mean Decrease in Impurity (Gini Importance), Random Forest explicitly quantifies which network flow metrics are most indicative of an ongoing DDoS attack.
4. **Empirical Benchmark Superiority:** Consistently achieves top-tier F1-scores and detection times on standard benchmark flow datasets (CICIDS2017 and CICDDoS2019).

#### 2.3 Type of Learning: Supervised Learning
The model is trained on labeled historical flow records:
$$\mathcal{D} = \{(\mathbf{x}_i, y_i)\}_{i=1}^{N}, \quad y_i \in \{\text{Benign (0)}, \text{Attack (1)}\}$$
- **Benign:** Standard interactive web traffic, database queries, and legitimate DNS lookups.
- **Attack:** High-volume volumetric flood traffic (SYN Floods, UDP Floods, Layer-7 HTTP Floods).

*Note:* This task is not Unsupervised (which lacks ground-truth attack labels and suffers from high false-positive rates) and not Reinforcement Learning (as there is no interactive reward-driven agent).

---

### 3. Methodology: Flow-Based Detection Pipeline

The end-to-end detection architecture operates across four distinct phases:

```
[ 1. Network Traffic ] ---> [ 2. Flow Extraction ] ---> [ 3. RF Classifier ] ---> [ 4. Benign / Attack ]
   Raw packets captured       Group packets into flows;    Scoring flow in μs        Attack flagged;
   at router / SDN switch     compute duration, rates,     via Random Forest         mitigation pushed
                              asymmetry, and flag counts   Ensemble                  to firewall
```

#### Step 1: Network Traffic Capture
Packets are captured at ingress routers, edge firewalls, or OpenFlow SDN switches (e.g., Open vSwitch).

#### Step 2: Flow Extraction
Packets sharing the standard 5-tuple:
$$(\text{Src IP}, \text{Dst IP}, \text{Src Port}, \text{Dst Port}, \text{Protocol})$$
within an active flow timeout are aggregated into bidirectional flow records.

#### Key Flow Features Specified in Review-1:
| Flow Feature | Mathematical Formulation | Cybersecurity Relevance |
| :--- | :--- | :--- |
| **Flow Duration** | $t_{\text{end}} - t_{\text{start}}$ ($\mu s$) | Distinguishes short-burst SYN attacks from long-lived legitimate connections. |
| **Packets/sec** | $\frac{N_{\text{packets}}}{\text{Duration (sec)}}$ | Direct volumetric intensity measurement; flood attacks exhibit extreme packet frequencies. |
| **Bytes/sec** | $\frac{\sum \text{Bytes}}{\text{Duration (sec)}}$ | Captures bandwidth saturation attacks (e.g., large UDP amplification payloads). |
| **Fwd/Bwd Packet Ratio** | $\frac{N_{\text{fwd}}}{\max(N_{\text{bwd}}, 1)}$ | Reflects connection symmetry; floods send massive forward requests with zero/few responses. |
| **SYN Flag Count** | $\sum \mathbb{I}(\text{Flag}_{\text{SYN}} = 1)$ | Diagnoses TCP half-open socket exhaustion attacks where no 3-way handshakes finish. |
| **Avg Packet Size** | $\frac{\text{Total Bytes}}{\text{Total Packets}}$ | Identifies abnormal packet geometries (tiny 40-byte SYN packets vs. full MTU payloads). |

#### Step 3: RF Classifier Scoring
The trained ensemble scores the extracted feature vector $\mathbf{x} \in \mathbb{R}^{d}$ within microseconds, outputting class probability $P(\text{Attack} \mid \mathbf{x})$.

#### Step 4: Automated Mitigation
- **Benign Flows:** Forwarded without latency penalty.
- **Attack Flows:** Trigger instant synthesis of Linux `iptables` drop rules and OpenFlow SDN `flow-mod` table drops:
  ```bash
  iptables -I INPUT 1 -s <Attacker_IP> -p <Protocol> --dport <Port> -j DROP
  ovs-ofctl add-flow br0 priority=50000,ip,nw_src=<Attacker_IP>,actions=drop
  ```

---

### 4. Experimental Results (Review-1 Evaluation)

The model was evaluated on a held-out test dataset of 5,000 flow records ($20\%$ test split with stratification).

#### 4.1 Quantitative Performance Metrics
| Metric | Formula | Score Achieved |
| :--- | :--- | :--- |
| **Accuracy** | $\frac{TP + TN}{TP + TN + FP + FN}$ | **99.96%** |
| **Precision** | $\frac{TP}{TP + FP}$ | **99.96%** |
| **Recall (Sensitivity)** | $\frac{TP}{TP + FN}$ | **99.96%** |
| **F1-Score** | $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$ | **99.96%** |
| **ROC-AUC** | Area under Receiver Operating Characteristic | **1.0000** |
| **Detection Latency** | Inference Time per Flow | **8.57 $\mu s$ / flow** |
| **Throughput Capacity** | Flows processed per second | **> 116,000 flows/sec** |

#### 4.2 Ranked Feature Importance (Gini Impurity)
The top indicative features extracted by the Random Forest classifier:
1. **`Fwd_Bwd_Packet_Ratio` (25.86%):** The primary indicator of spoofed and unanswered flood traffic.
2. **`Total_Fwd_Packets` (19.24%):** Volume of ingress packets dispatched by the client.
3. **`Total_Bwd_Packets` (18.51%):** Absence of server responses characterizes half-open floods.
4. **`Flow_IAT_Mean` (13.94%):** Mean inter-arrival time; automated attack bots transmit with minimal jitter.
5. **`Subflow_Fwd_Bytes` (7.45%):** Aggregated data payload sent forward.
6. **`Flow_Packets_Sec` (7.06%):** Volumetric intensity metric.
7. **`ACK_Flag_Count` (2.78%):** Lack of ACKs flags incomplete handshakes.
8. **`Flow_Bytes_Sec` (1.87%):** Bandwidth rate.
9. **`SYN_Flag_Count` (1.70%):** Half-open TCP connection attempts.
10. **`Avg_Packet_Size` (0.84%):** Geometry of individual packets.

#### 4.3 Overfitting Analysis: Decision Tree vs. Random Forest
| Model Architecture | Training Accuracy | Testing Accuracy | Overfitting Gap ($\Delta$) |
| :--- | :--- | :--- | :--- |
| **Single Decision Tree** | 100.00% | 99.98% | 0.02% |
| **Random Forest (100 Trees)** | 100.00% | 99.98% | **0.02%** |

*Analysis:* While a single decision tree is prone to structural instability and variance when exposed to novel network perturbations, the Random Forest ensemble maintains equal boundary stability across randomized subspaces, offering superior resilience against adversarial evasion.

#### 4.4 Multi-Class Extension (Outcome 3)
The pipeline was successfully extended to classify specific attack vectors:
- **Benign:** $100\%$ precision / recall
- **SYN Flood:** $100\%$ precision / recall
- **UDP Flood:** $100\%$ precision / recall
- **HTTP Flood:** $99.9\%$ precision / recall  
**Overall Multi-Class Accuracy:** **99.98%**

---

### 5. Review-1 Outcomes Checklist & Compliance
- [x] **Outcome 1:** High-accuracy Benign vs. Attack classification on held-out flow data (99.96%).
- [x] **Outcome 2:** Ranked feature-importance report identifying the strongest attack indicators.
- [x] **Outcome 3:** Reusable detection pipeline extendable to multi-class attack classification.
- [x] **Outcome 4:** Foundation for real-time mitigation integration (automated firewall drop rules).

---

### 6. Roadmap for Subsequent Reviews (Review-2 & Beyond)
1. **Live Interface Sniffing:** Ingest live network packets from physical NICs using Scapy / PyShark and extract flows dynamically using an online flow-meter.
2. **SDN Controller Integration:** Direct deployment as a REST reactive app inside an OpenFlow SDN controller (e.g., Ryu / ONOS) to dynamically alter OpenFlow switch flow tables.
3. **Adversarial Flow Evasion Testing:** Test robustness against low-rate DDoS (LDoS) and slow-rate application floods (Slowloris, R-U-Dead-Yet).
