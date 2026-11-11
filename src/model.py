"""
MLCS PBL - DDoS Detection Using Flow Data
Model Module: Random Forest Classifier

Implements supervised ensemble learning for network flow classification,
evaluates detection latency, generates feature-importance rankings,
and provides multi-class extensibility.
"""

import time
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)


class DDoSFlowClassifier:
    """
    Supervised Flow-based DDoS Detection Model using Random Forest.
    """
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: Optional[int] = 16,
        min_samples_split: int = 4,
        random_state: int = 42,
        class_weight: str = "balanced",
        feature_names: Optional[List[str]] = None
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.random_state = random_state
        self.class_weight = class_weight
        self.feature_names = feature_names or []
        
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            min_samples_split=self.min_samples_split,
            random_state=self.random_state,
            class_weight=self.class_weight,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]] = None) -> "DDoSFlowClassifier":
        """Train the Random Forest ensemble on labeled flow records."""
        if feature_names:
            self.feature_names = feature_names
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Classify flows into Benign (0) or Attack (1)."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predicting.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability distributions."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predicting probabilities.")
        return self.model.predict_proba(X)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """
        Comprehensive evaluation measuring classification quality and detection latency.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before evaluation.")

        # Measure detection latency
        start_time = time.perf_counter()
        y_pred = self.model.predict(X_test)
        total_inference_time = time.perf_counter() - start_time
        latency_per_flow_us = (total_inference_time / len(X_test)) * 1_000_000.0  # microseconds

        y_prob = self.model.predict_proba(X_test)
        is_binary = len(np.unique(y_test)) == 2

        accuracy = float(accuracy_score(y_test, y_pred))
        
        if is_binary:
            precision = float(precision_score(y_test, y_pred, zero_division=0))
            recall = float(recall_score(y_test, y_pred, zero_division=0))
            f1 = float(f1_score(y_test, y_pred, zero_division=0))
            roc_auc = float(roc_auc_score(y_test, y_prob[:, 1]))
        else:
            precision = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
            recall = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
            f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
            roc_auc = float(roc_auc_score(y_test, y_prob, multi_class="ovr", average="weighted"))

        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        metrics = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "detection_latency_per_flow_us": round(latency_per_flow_us, 2),
            "total_test_samples": len(X_test),
            "total_inference_time_sec": round(total_inference_time, 4),
            "confusion_matrix": cm.tolist(),
            "classification_report": report
        }
        return metrics

    def get_feature_importances(self) -> pd.DataFrame:
        """
        Rank flow features by Mean Decrease in Impurity (Gini importance).
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted to obtain feature importances.")
        
        importances = self.model.feature_importances_
        feature_names = self.feature_names if self.feature_names else [f"Feature_{i}" for i in range(len(importances))]
        
        fi_df = pd.DataFrame({
            "Feature": feature_names,
            "Importance": importances,
            "Percentage": (importances / importances.sum()) * 100.0
        }).sort_values(by="Importance", ascending=False).reset_index(drop=True)
        
        return fi_df

    def save(self, filepath: str) -> None:
        """Serialize model and metadata to disk."""
        data = {
            "model": self.model,
            "feature_names": self.feature_names,
            "params": {
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "min_samples_split": self.min_samples_split,
                "random_state": self.random_state,
                "class_weight": self.class_weight
            },
            "is_fitted": self.is_fitted
        }
        joblib.dump(data, filepath)

    @classmethod
    def load(cls, filepath: str) -> "DDoSFlowClassifier":
        """Deserialize trained model from disk."""
        data = joblib.load(filepath)
        instance = cls(
            n_estimators=data["params"]["n_estimators"],
            max_depth=data["params"]["max_depth"],
            min_samples_split=data["params"]["min_samples_split"],
            random_state=data["params"]["random_state"],
            class_weight=data["params"]["class_weight"],
            feature_names=data["feature_names"]
        )
        instance.model = data["model"]
        instance.is_fitted = data["is_fitted"]
        return instance


def compare_with_single_decision_tree(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray
) -> Dict[str, Any]:
    """
    Compares Random Forest with Single Decision Tree as requested in Review-1
    (Bagging + Feature Randomness vs Overfitting).
    """
    # 1. Single Decision Tree
    dt = DecisionTreeClassifier(random_state=42)
    dt.fit(X_train, y_train)
    dt_train_acc = accuracy_score(y_train, dt.predict(X_train))
    dt_test_acc = accuracy_score(y_test, dt.predict(X_test))
    
    # 2. Random Forest
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_train_acc = accuracy_score(y_train, rf.predict(X_train))
    rf_test_acc = accuracy_score(y_test, rf.predict(X_test))

    return {
        "Decision_Tree": {
            "train_accuracy": float(dt_train_acc),
            "test_accuracy": float(dt_test_acc),
            "overfitting_gap": float(dt_train_acc - dt_test_acc)
        },
        "Random_Forest": {
            "train_accuracy": float(rf_train_acc),
            "test_accuracy": float(rf_test_acc),
            "overfitting_gap": float(rf_train_acc - rf_test_acc)
        }
    }
