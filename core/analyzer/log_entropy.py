import math
import re
from collections import Counter
from typing import Dict, Any


class LogEntropyAnalyzer:
    BASE64_REGEX = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
    HEX_REGEX = re.compile(r"(?:0x)?[A-Fa-f0-9]{16,}")

    def __init__(self, base=2):
        self.base = base

    def shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0

        # Normalize: collapse whitespace, strip logs
        cleaned = data.strip()
        if not cleaned:
            return 0.0

        counter = Counter(cleaned)
        total = len(cleaned)

        entropy = -sum(
            (count / total) * math.log(count / total, self.base)
            for count in counter.values()
        )
        return round(entropy, 4)

    def analyze_log(self, log: str, threshold: float = 4.5) -> Dict[str, Any]:
        """
        Returns:
            {
                "entropy": float,
                "is_suspicious": bool,
                "base64_matches": [...],
                "hex_matches": [...],
                "length": int
            }
        """

        entropy_value = self.shannon_entropy(log)

        base64_matches = self.BASE64_REGEX.findall(log)
        hex_matches = self.HEX_REGEX.findall(log)

        return {
            "entropy": entropy_value,
            "is_suspicious": entropy_value > threshold or bool(base64_matches) or bool(hex_matches),
            "base64_matches": base64_matches,
            "hex_matches": hex_matches,
            "length": len(log),
        }


# Example usage
if __name__ == "__main__":
    analyzer = LogEntropyAnalyzer()
    log_sample = "aHR0cDovL2V2aWwubmV0L2NnaS1iaW4vc2hlbGw="
    result = analyzer.analyze_log(log_sample)

    print("Analysis:", result)
