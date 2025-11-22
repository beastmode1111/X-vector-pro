# core/analyzer.py

import json
import statistics
from typing import Any, Dict, List, Optional

from core.logger import get_logger, log_event

logger = get_logger("Analyzer")


class Analyzer:
    """
    Safe, production-ready analysis engine for XVectorPro.
    This analyzes *your own tool outputs* and generates structured insights.
    """

    def __init__(self):
        self.results: Dict[str, Any] = {}
        logger.info("Analyzer initialized")

    # ---------------------------------------------
    # Data ingestion
    # ---------------------------------------------
    def add_result(self, category: str, data: Any):
        """
        Add raw output from any step (scanner, recon, etc.)
        """
        logger.info(f"Adding result for category: {category}")

        self.results[category] = data

        log_event(
            category=f"analyzer_add_{category}",
            data={"stored": True, "content": data},
            level="info"
        )

    # ---------------------------------------------
    # General statistics extractor
    # ---------------------------------------------
    def compute_basic_stats(self, values: List[float]) -> Dict[str, float]:
        """
        Safely compute numeric stats: min, max, average, median.
        """

        logger.info("Computing basic statistics")

        if not values:
            logger.warning("Empty list passed to compute_basic_stats")
            return {"min": 0, "max": 0, "average": 0, "median": 0}

        try:
            stats = {
                "min": float(min(values)),
                "max": float(max(values)),
                "average": float(sum(values) / len(values)),
                "median": float(statistics.median(values)),
            }

            log_event(
                category="stats_basic",
                data={"values": values, "results": stats},
                level="info"
            )

            return stats

        except Exception as e:
            logger.error(f"Stat computation failed: {e}")
            return {"min": 0, "max": 0, "average": 0, "median": 0}

    # ---------------------------------------------
    # High-level summary generator
    # ---------------------------------------------
    def summarize(self) -> Dict[str, Any]:
        """
        Generates a high-level summary of all stored results.
        Example use: attach to final report object.
        """

        logger.info("Building analyzer summary")

        summary = {
            "categories": list(self.results.keys()),
            "entry_count": len(self.results),
            "timestamp": json.dumps({})
        }

        # Add dynamic, per-category metrics
        detailed = {}
        for category, data in self.results.items():
            detailed[category] = {
                "type": str(type(data).__name__),
                "length": len(data) if hasattr(data, "__len__") else None,
            }

        summary["details"] = detailed

        log_event(
            category="analyzer_summary",
            data=summary,
            level="info"
        )

        return summary

    # ---------------------------------------------
    # Export results to JSON
    # ---------------------------------------------
    def export(self, path: str) -> Optional[str]:
        """
        Save results to JSON for later ingestion by report engine.
        """

        logger.info(f"Exporting analyzer results → {path}")

        try:
            with open(path, "w") as f:
                json.dump(self.results, f, indent=4)

            log_event(
                category="analyzer_export",
                data={"path": path, "status": "ok"},
                write_structured_file=True
            )

            return path

        except Exception as e:
            logger.error(f"Failed to export analyzer JSON: {e}")
            return None
