# x-vector-pro/core/analyzer/ai_correlation.py
"""
AI Correlation - Cyber Defense edition

Purpose:
- Analyze telemetry (flow logs, netflow/Zeek CSV/JSON, host metrics) to compute correlations,
  train models to prioritize features, and detect anomalous flows/hosts.
- Designed to be used as a utility in cyber defense pipelines (SIEM, EDR, SOC tooling).

Key cyber-specific behaviors:
- Accepts DataFrame / CSV / JSON of flow-like records (src_ip, dst_ip, src_port, dst_port,
  protocol, bytes, packets, start_time, end_time, duration, label/is_malicious).
- Provides aggregation utilities (per-IP, per-endpoint, per-time-window).
- Produces correlation matrices for numeric features, feature importances (if supervised),
  isolation-forest anomaly scores and per-record anomaly flags.

Usage example:
    from x_vector_pro.core.analyzer.ai_correlation import AICorrelation
    analyzer = AICorrelation(target_col="is_malicious", time_col="start_time", domain="cyber")
    report = analyzer.run_pipeline("flows.csv", supervised=True, use_rolling=True)
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Optional, Sequence, Dict, Any, Tuple, List
import numpy as np
import pandas as pd
import warnings

# sklearn imports
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.preprocessing import StandardScaler

# defaults
DEFAULT_NUM_ESTIMATORS = 200
DEFAULT_RANDOM_STATE = 42

# --- Utility helpers (cyber-focused) ---


def _safe_ip_agg_key(ip: str) -> str:
    """Normalize IP key for grouping (placeholder, keep deterministic)."""
    return str(ip).strip()


def _ports_to_service_hint(port: int) -> str:
    """Very simple heuristic mapping common ports to service hints (extend as needed)."""
    try:
        port = int(port)
    except Exception:
        return "other"
    if port in (80, 8080, 443):
        return "web"
    if port in (22, 2222):
        return "ssh"
    if port in (23,):
        return "telnet"
    if port in (53,):
        return "dns"
    if port in (25, 587, 465):
        return "smtp"
    if 0 < port < 1024:
        return "system"
    if 1024 <= port < 49152:
        return "ephemeral"
    return "other"


@dataclass
class AICorrelation:
    """
    Cyber-aware AI Correlation class.

    Args:
        target_col: supervised target (e.g., 'is_malicious' boolean/int). If None, skip supervised.
        time_col: name of timestamp column (e.g., 'start_time' or 'ts'). If present, sorting and rolling features enabled.
        feature_cols: explicit list of features to use (inferred automatically if None).
        domain: 'cyber' toggles cyber-specific feature engineering defaults.
        classifier: 'rf' uses RandomForestClassifier by default for supervised; change later if needed.
    """
    target_col: Optional[str] = "is_malicious"
    time_col: Optional[str] = "start_time"
    feature_cols: Optional[Sequence[str]] = None
    test_size: float = 0.2
    random_state: int = DEFAULT_RANDOM_STATE
    rf_n_estimators: int = DEFAULT_NUM_ESTIMATORS
    domain: str = "cyber"  # enables cyber feature engineering
    scaler: Optional[StandardScaler] = field(default=None, init=False)
    clf_model: Optional[RandomForestClassifier] = field(default=None, init=False)
    iso_model: Optional[IsolationForest] = field(default=None, init=False)

    # --- data loaders / parsers ---
    def load_data(self, data: Any) -> pd.DataFrame:
        """
        Accepts:
            - pd.DataFrame
            - path to CSV/JSON/NDJSON
            - list/dict
        Ensures timestamp parsing for time_col and coerces numeric columns where appropriate.
        """
        if isinstance(data, pd.DataFrame):
            df = data.copy()
        elif isinstance(data, str):
            path = data
            if path.lower().endswith(".csv"):
                df = pd.read_csv(path)
            elif path.lower().endswith((".json", ".ndjson")):
                df = pd.read_json(path, lines=path.lower().endswith(".ndjson"))
            else:
                # try CSV then JSON
                try:
                    df = pd.read_csv(path)
                except Exception:
                    df = pd.read_json(path, lines=False)
        elif isinstance(data, (list, dict)):
            df = pd.DataFrame(data)
        else:
            raise ValueError("Unsupported data type for load_data")

        # Normalize common cyber column names
        lower_cols = {c.lower(): c for c in df.columns}
        mapping = {}
        for canonical in ("start_time", "end_time", "timestamp", "ts"):
            if canonical in lower_cols and self.time_col not in df.columns:
                mapping[lower_cols[canonical]] = self.time_col or canonical
        if mapping:
            df = df.rename(columns=mapping)

        if self.time_col and self.time_col in df.columns:
            df[self.time_col] = pd.to_datetime(df[self.time_col], errors="coerce")
            df = df.sort_values(self.time_col).reset_index(drop=True)

        # numeric coercion for bytes/packets/duration if present
        for c in ("bytes", "packets", "duration", "pkt_size", "flow_bytes"):
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce")
        # ports to int where possible
        for pcol in ("src_port", "dst_port", "sport", "dport"):
            if pcol in df.columns:
                df[pcol] = pd.to_numeric(df[pcol], errors="coerce")

        return df

    # --- cyber feature engineering ---
    def basic_cyber_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add typical derived features used in cyber analysis:
          - bytes_per_packet
          - duration (if not present, try to infer from start/end)
          - src/dst service hint (from port)
          - flag rare ports/services (binary)
        """
        df = df.copy()
        # bytes_per_packet
        if "bytes" in df.columns and "packets" in df.columns:
            df["bytes_per_packet"] = df.apply(
                lambda r: (r["bytes"] / r["packets"]) if pd.notnull(r["bytes"]) and pd.notnull(r["packets"]) and r["packets"] > 0 else 0.0,
                axis=1
            )
        # duration
        if "duration" not in df.columns:
            if ("end_time" in df.columns) and (self.time_col in df.columns):
                df["duration"] = (pd.to_datetime(df["end_time"], errors="coerce") - pd.to_datetime(df[self.time_col], errors="coerce")).dt.total_seconds().fillna(0)
            else:
                # fallback: 0 or nan
                df["duration"] = df.get("duration", 0).fillna(0)

        # rates
        df["bytes_per_sec"] = df.apply(lambda r: (r.get("bytes", 0) / r.get("duration", 1)) if r.get("duration", 0) > 0 else r.get("bytes", 0), axis=1)
        df["pkts_per_sec"] = df.apply(lambda r: (r.get("packets", 0) / r.get("duration", 1)) if r.get("duration", 0) > 0 else r.get("packets", 0), axis=1)

        # service hints from ports (very small heuristic)
        if "src_port" in df.columns:
            df["src_svc_hint"] = df["src_port"].apply(lambda p: _ports_to_service_hint(p))
        if "dst_port" in df.columns:
            df["dst_svc_hint"] = df["dst_port"].apply(lambda p: _ports_to_service_hint(p))

        # encode common protocols as numeric categories if present
        if "protocol" in df.columns:
            df["protocol_norm"] = df["protocol"].astype(str).str.lower().fillna("unk")
            df["protocol_code"] = pd.factorize(df["protocol_norm"])[0]

        # high-risk port hint flag (common exfil ports or high risk)
        high_risk_ports = {22, 23, 3389, 5900, 21}
        if "dst_port" in df.columns:
            df["dst_high_risk_port"] = df["dst_port"].apply(lambda p: 1 if (pd.notnull(p) and int(p) in high_risk_ports) else 0)

        # convert boolean-ish labels to ints if present
        if self.target_col and self.target_col in df.columns:
            df[self.target_col] = df[self.target_col].apply(lambda v: 1 if v in (1, "1", True, "true", "True", "TRUE") else 0)

        return df

    def aggregate_by_ip(self, df: pd.DataFrame, ip_col: str = "src_ip", window_sec: int = 60) -> pd.DataFrame:
        """
        Simple aggregation over sliding windows grouped by ip_col. This is a row-aggregation
        helper: for each flow/row, compute counts/bytes over the prior window_sec seconds for that IP.
        Note: works best when df is sorted by time_col.
        """
        if self.time_col is None or self.time_col not in df.columns:
            raise ValueError("time_col required for temporal aggregation")

        df = df.copy()
        df = df.sort_values(self.time_col).reset_index(drop=True)
        # initialize aggregated columns
        df["_agg_count_last_window"] = 0
        df["_agg_bytes_last_window"] = 0.0

        # for performance on large datasets you would replace this loop with optimized rolling/groupby logic;
        # we'll implement a simple pointer-scan per IP that's deterministic and safe.
        grouped = {}
        time_vals = df[self.time_col].values
        for idx, row in df.iterrows():
            ip = _safe_ip_agg_key(row.get(ip_col, ""))
            t = row[self.time_col].to_datetime64() if hasattr(row[self.time_col], "to_datetime64") else np.datetime64(row[self.time_col])
            if ip not in grouped:
                grouped[ip] = []
            # remove old entries
            cutoff = t - np.timedelta64(int(window_sec), 's')
            # keep only events >= cutoff
            grouped[ip] = [entry for entry in grouped[ip] if entry[0] >= cutoff]
            # compute aggregates
            agg_count = len(grouped[ip])
            agg_bytes = sum(float(entry[1]) for entry in grouped[ip]) if grouped[ip] else 0.0
            df.at[idx, "_agg_count_last_window"] = agg_count
            df.at[idx, "_agg_bytes_last_window"] = agg_bytes
            # append current
            grouped[ip].append((t, float(row.get("bytes", 0) or 0.0)))
        return df

    # --- generic utilities retained from original ML-first design ---
    def infer_feature_columns(self, df: pd.DataFrame) -> Sequence[str]:
        if self.feature_cols:
            return [c for c in self.feature_cols if c in df.columns]
        exclude = {self.time_col, self.target_col}
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        # include engineered numeric features even if they are new
        return [c for c in numeric_cols if c not in exclude]

    def impute_and_clean(self, df: pd.DataFrame, fill_method: str = "ffill") -> pd.DataFrame:
        df = df.copy()
        if self.time_col and self.time_col in df.columns:
            df = df.sort_values(self.time_col).reset_index(drop=True)
            # forward/backfill for timeseries continuity
            df = df.fillna(method="ffill").fillna(method="bfill")
        else:
            for col in df.select_dtypes(include=[np.number]).columns:
                df[col] = df[col].fillna(df[col].median())
        return df

    def compute_correlations(self, df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        numeric = df.select_dtypes(include=[np.number])
        pearson = numeric.corr(method="pearson")
        spearman = numeric.corr(method="spearman")
        return {"pearson": pearson, "spearman": spearman}

    def build_feature_matrix(self, df: pd.DataFrame, use_rolling: bool = True, rolling_windows: Sequence[int] = (3, 5, 10)) -> Tuple[pd.DataFrame, Sequence[str]]:
        df = df.copy()
        # cyber-specific engineering
        if self.domain == "cyber":
            df = self.basic_cyber_features(df)
            # temporal aggregation per src_ip as default
            try:
                df = self.aggregate_by_ip(df, ip_col="src_ip", window_sec=60)
            except Exception:
                # if missing time or src_ip, skip gracefully
                pass

        # rolling features (if time series)
        if use_rolling and self.time_col in df.columns:
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            for w in rolling_windows:
                rolled = df[numeric_cols].rolling(window=w, min_periods=1)
                df = pd.concat([df, rolled.mean().add_suffix(f"_roll{w}_mean")], axis=1)
        features = self.infer_feature_columns(df)
        X = df[features].copy().fillna(0)
        return X, features

    # supervised training uses classifier (RandomForestClassifier)
    def train_supervised(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """
        Train classifier (RandomForest) to estimate feature importances.
        Returns metrics including ROC-AUC if binary labels are provided.
        """
        if y.nunique() <= 1:
            warnings.warn("Target has <=1 unique value; supervised training skipped.")
            return {"model": None, "metrics": {}, "importances": pd.DataFrame()}

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.test_size, random_state=self.random_state, stratify=y if y.nunique() > 1 else None
        )

        self.scaler = StandardScaler()
        X_train_s = self.scaler.fit_transform(X_train)
        X_test_s = self.scaler.transform(X_test)

        self.clf_model = RandomForestClassifier(
            n_estimators=self.rf_n_estimators, random_state=self.random_state, n_jobs=-1
        )
        self.clf_model.fit(X_train_s, y_train)

        y_pred_proba = None
        metrics = {}
        try:
            y_pred_proba = self.clf_model.predict_proba(X_test_s)[:, 1]
            metrics["roc_auc"] = float(roc_auc_score(y_test, y_pred_proba))
        except Exception:
            # classifier might not support predict_proba
            try:
                y_pred = self.clf_model.predict(X_test_s)
                metrics["accuracy"] = float(accuracy_score(y_test, y_pred))
            except Exception:
                pass

        importances = pd.DataFrame({
            "feature": X.columns,
            "importance": getattr(self.clf_model, "feature_importances_", np.zeros(X.shape[1]))
        }).sort_values("importance", ascending=False).reset_index(drop=True)

        return {"model": self.clf_model, "metrics": metrics, "importances": importances}

    def train_anomaly_detector(self, X: pd.DataFrame, contamination: float = 0.01) -> Dict[str, Any]:
        """
        Train IsolationForest (unsupervised) on numeric features scaled.
        Returns model, scores, and anomaly flags (-1 anomaly, 1 normal).
        """
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_s = self.scaler.fit_transform(X)
        else:
            X_s = self.scaler.transform(X)

        self.iso_model = IsolationForest(contamination=contamination, random_state=self.random_state)
        self.iso_model.fit(X_s)
        scores = self.iso_model.decision_function(X_s)
        anomalies = self.iso_model.predict(X_s)
        return {"model": self.iso_model, "scores": scores, "anomalies": anomalies}

    def score_anomalies(self, df: pd.DataFrame, X: pd.DataFrame) -> pd.DataFrame:
        if self.iso_model is None or self.scaler is None:
            raise RuntimeError("Anomaly detector or scaler not trained")
        X_s = self.scaler.transform(X)
        scores = self.iso_model.decision_function(X_s)
        flags = self.iso_model.predict(X_s)
        res = df.copy()
        res["_anomaly_score"] = scores
        res["_anomaly_flag"] = (flags == -1).astype(int)
        return res

    def run_pipeline(
        self,
        data: Any,
        supervised: bool = True,
        anomaly_contamination: float = 0.01,
        use_rolling: bool = True
    ) -> Dict[str, Any]:
        """
        Full pipeline for cyber-defense use cases.

        Returns:
          - df: cleaned dataframe (engineered columns included)
          - correlations: pearson & spearman matrices
          - features: list of used numeric features
          - supervised: metrics + importances (if run)
          - anomaly: raw anomaly outputs
          - df_with_anomalies: original df with '_anomaly_score' and '_anomaly_flag'
        """
        df = self.load_data(data)
        df = self.impute_and_clean(df)

        X, features = self.build_feature_matrix(df, use_rolling=use_rolling)
        correlations = self.compute_correlations(pd.concat([df[features], X], axis=1))

        result: Dict[str, Any] = {
            "df": df,
            "correlations": correlations,
            "features": list(features),
        }

        if supervised and self.target_col and self.target_col in df.columns:
            y = df[self.target_col].fillna(0).astype(int)
            sup = self.train_supervised(X, y)
            result["supervised"] = {"metrics": sup["metrics"], "importances": sup["importances"]}
        else:
            result["supervised"] = None

        anomaly_res = self.train_anomaly_detector(X, contamination=anomaly_contamination)
        result["anomaly"] = {"scores": anomaly_res["scores"], "anomalies": anomaly_res["anomalies"]}
        result["df_with_anomalies"] = self.score_anomalies(df, X)

        return result


# CLI sample for quick runs and testing
def _example_pipeline(csv_path: str):
    import pathlib
    path = pathlib.Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(csv_path)
    df = pd.read_csv(str(path))
    analyzer = AICorrelation(target_col="is_malicious", time_col="start_time", domain="cyber")
    report = analyzer.run_pipeline(df, supervised=True, anomaly_contamination=0.02)
    print("Correlations (pearson) top absolute pairs:")
    p = report["correlations"]["pearson"].abs().unstack().sort_values(ascending=False)
    p = p[p > 0]
    # remove self correlations by name and duplicates
    dedup = p[~p.index.duplicated()]
    print(dedup.head(20))
    if report["supervised"]:
        print("Supervised metrics:", report["supervised"]["metrics"])
        print("Top features:")
        print(report["supervised"]["importances"].head(10).to_string(index=False))
    print("Anomalies detected:", int(report["df_with_anomalies"]["_anomaly_flag"].sum()))
    # show sample anomalies
    print(report["df_with_anomalies"].loc[report["df_with_anomalies"]["_anomaly_flag"] == 1].head(5))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ai_correlation.py <flows.csv>")
        print("Expected columns (recommended): src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,start_time,end_time,is_malicious")
    else:
        _example_pipeline(sys.argv[1])
