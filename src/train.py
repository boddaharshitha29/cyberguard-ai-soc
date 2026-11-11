"""
MLCS PBL - DDoS Detection Using Flow Data
Training Pipeline Script

Executes model training, evaluation on held-out test data,
generates feature-importance reports, performs Decision Tree vs Random Forest
overfitting comparison, and persists artifacts.
"""

import os
import sys

# Ensure workspace root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Set matplotlib cache directory to avoid permission warnings
os.environ["MPLCONFIGDIR"] = os.path.join(BASE_DIR, ".matplotlib_cache")
os.makedirs(os.environ["MPLCONFIGDIR"], exist_ok=True)

import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd

from src.data_generator import generate_flow_dataset
from src.preprocessing import prepare_flow_data, KEY_REVIEW1_FEATURES, ALL_FLOW_FEATURES
from src.model import DDoSFlowClassifier, compare_with_single_decision_tree


def plot_confusion_matrix(cm, labels, save_path):
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.title("Confusion Matrix - DDoS Flow Classification", fontsize=13, fontweight="bold")
    plt.xlabel("Predicted Label", fontsize=11)
    plt.ylabel("Actual Ground Truth", fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()


def plot_feature_importance(fi_df, save_path):
    plt.figure(figsize=(9, 5))
    sns.barplot(data=fi_df.head(10), x="Importance", y="Feature", palette="viridis")
    plt.title("Top Ranked Flow Features (Random Forest Gini Importance)", fontsize=13, fontweight="bold")
    plt.xlabel("Gini Impurity Importance", fontsize=11)
    plt.ylabel("Network Flow Feature", fontsize=11)
    for index, value in enumerate(fi_df.head(10)["Importance"]):
        plt.text(value + 0.005, index, f"{value:.4f}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()


def run_training_pipeline():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    raw_data_dir = os.path.join(base_dir, "data", "raw")
    models_dir = os.path.join(base_dir, "models")
    plots_dir = os.path.join(base_dir, "models", "plots")
    
    os.makedirs(raw_data_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(plots_dir, exist_ok=True)

    csv_path = os.path.join(raw_data_dir, "network_flows.csv")
    if not os.path.exists(csv_path):
        print("[Pipeline] Raw flow dataset not found. Generating new benchmark flow dataset...")
        generate_flow_dataset(n_samples=25000, benign_ratio=0.5, random_state=42, output_path=csv_path)

    print("\n" + "="*70)
    print("      MLCS PBL: DDoS FLOW CLASSIFICATION (REVIEW-1 TRAINING RUN)      ")
    print("="*70)

    # 1. Prepare Binary Classification Data
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    X_train, X_test, y_train, y_test, features, scaler = prepare_flow_data(
        csv_path=csv_path,
        feature_cols=ALL_FLOW_FEATURES,
        target_col="Binary_Label",
        test_size=0.20,
        random_state=42,
        scale_features=False,  # Random forest operates directly on features
        scaler_save_path=scaler_path
    )

    # 2. Train Random Forest Classifier
    print(f"\n[1] Training Random Forest Ensemble on {X_train.shape[0]} flow records...")
    rf_clf = DDoSFlowClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        feature_names=features
    )
    rf_clf.fit(X_train, y_train, feature_names=features)

    # 3. Evaluate on Held-Out Test Data
    print(f"[2] Evaluating on {X_test.shape[0]} held-out test flows...")
    metrics = rf_clf.evaluate(X_test, y_test)

    print("\n" + "-"*50)
    print("           MODEL PERFORMANCE METRICS")
    print("-"*50)
    print(f"  * Classification Accuracy : {metrics['accuracy'] * 100:.2f}%")
    print(f"  * Precision Score         : {metrics['precision'] * 100:.2f}%")
    print(f"  * Recall (Sensitivity)    : {metrics['recall'] * 100:.2f}%")
    print(f"  * F1-Score (Harmonic Mean): {metrics['f1_score'] * 100:.2f}%")
    print(f"  * ROC-AUC Score           : {metrics['roc_auc']:.4f}")
    print(f"  * Flow Latency            : {metrics['detection_latency_per_flow_us']:.2f} microseconds/flow")
    print(f"  * Total Test Inference    : {metrics['total_inference_time_sec']:.4f} seconds ({metrics['total_test_samples']} flows)")
    print("-"*50)

    # 4. Feature Importance Ranking
    print("\n[3] Calculating Ranked Flow Feature Importance:")
    fi_df = rf_clf.get_feature_importances()
    print(fi_df.to_string(index=False))

    # 5. Overfitting Comparison (Decision Tree vs Random Forest)
    print("\n[4] Comparing Overfitting: Single Decision Tree vs Random Forest Ensemble:")
    comparison = compare_with_single_decision_tree(X_train, y_train, X_test, y_test)
    dt_gap = comparison["Decision_Tree"]["overfitting_gap"]
    rf_gap = comparison["Random_Forest"]["overfitting_gap"]
    print(f"  Decision Tree -> Train Acc: {comparison['Decision_Tree']['train_accuracy']*100:.2f}%, "
          f"Test Acc: {comparison['Decision_Tree']['test_accuracy']*100:.2f}% "
          f"(Overfitting Gap: {dt_gap*100:.2f}%)")
    print(f"  Random Forest -> Train Acc: {comparison['Random_Forest']['train_accuracy']*100:.2f}%, "
          f"Test Acc: {comparison['Random_Forest']['test_accuracy']*100:.2f}% "
          f"(Overfitting Gap: {rf_gap*100:.2f}%)")

    # 6. Multi-class Pipeline Extension (Outcome 3)
    print("\n[5] Training Multi-Class Extension (Benign vs SYN vs UDP vs HTTP Flood)...")
    df_raw = pd.read_csv(csv_path)
    attack_types = sorted(df_raw["Attack_Type"].unique())
    type_to_idx = {name: idx for idx, name in enumerate(attack_types)}
    y_multi = df_raw["Attack_Type"].map(type_to_idx).values
    
    from sklearn.model_selection import train_test_split
    X_m_tr, X_m_te, y_m_tr, y_m_te = train_test_split(
        df_raw[features].values, y_multi, test_size=0.20, random_state=42, stratify=y_multi
    )
    rf_multi = DDoSFlowClassifier(n_estimators=100, max_depth=16, random_state=42, feature_names=features)
    rf_multi.fit(X_m_tr, y_m_tr, feature_names=features)
    multi_metrics = rf_multi.evaluate(X_m_te, y_m_te)
    print(f"  * Multi-Class Accuracy: {multi_metrics['accuracy'] * 100:.2f}%")
    print(f"  * Multi-Class Weighted F1: {multi_metrics['f1_score'] * 100:.2f}%")

    # 7. Persist Models and Plots
    model_save_path = os.path.join(models_dir, "rf_ddos_model.joblib")
    multi_model_save_path = os.path.join(models_dir, "rf_multiclass_model.joblib")
    rf_clf.save(model_save_path)
    rf_multi.save(multi_model_save_path)
    
    cm_path = os.path.join(plots_dir, "confusion_matrix.png")
    plot_confusion_matrix(np.array(metrics["confusion_matrix"]), ["Benign", "Attack"], cm_path)

    fi_plot_path = os.path.join(plots_dir, "feature_importance.png")
    plot_feature_importance(fi_df, fi_plot_path)

    summary_results = {
        "binary_metrics": metrics,
        "feature_importance": fi_df.to_dict(orient="records"),
        "model_comparison": comparison,
        "multiclass_metrics": multi_metrics,
        "class_mapping_multiclass": type_to_idx
    }
    with open(os.path.join(models_dir, "training_summary.json"), "w") as f:
        json.dump(summary_results, f, indent=2)

    print(f"\n[6] All artifacts and plots successfully saved:")
    print(f"  - Model: {model_save_path}")
    print(f"  - Multi-class Model: {multi_model_save_path}")
    print(f"  - Metrics Summary: {os.path.join(models_dir, 'training_summary.json')}")
    print(f"  - Plots: {plots_dir}")
    print("="*70 + "\n")


if __name__ == "__main__":
    run_training_pipeline()
