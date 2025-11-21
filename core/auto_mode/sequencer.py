import logging
from core.recon import passive_recon
from core.scanner import run_port_scan
from core.brute import brute_force_login
from core.exploit_01 import run as run_exploit_01
from core.report import generate_report
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("operations_log.log")
    ]
)
logger = logging.getLogger(__name__)

def run_step(step_name: str, operation, target: str) -> str:
    """
    Executes a single step in the sequence and returns its result.
    Stops the sequencer if a critical error occurs.
    """
    logger.info(f"---- Starting {step_name} ----")
    
    try:
        result = operation(target)
        logger.info(f"✔ {step_name} completed")
        return f"[+] {step_name}:\n{result}"
    except Exception as e:
        logger.error(f"✘ {step_name} failed: {e}")
        raise RuntimeError(f"{step_name} failed: {e}")

def run_sequence(target: str = "127.0.0.1") -> str:
    """
    Executes all operations in strict order.
    Stops immediately if any step fails.
    """
    
    sequence_steps = [
        ("Passive Recon", passive_recon),
        ("Port Scan", run_port_scan),
        ("Brute Force Login", brute_force_login),
        ("Default Exploit", run_exploit_01),
        ("Report Generation", generate_report),
    ]

    results = []

    for step_name, operation in sequence_steps:
        logger.info(f"Running step: {step_name}")

        # Execute step — if it fails, the whole sequence stops
        step_output = run_step(step_name, operation, target)
        results.append(step_output)

    return "\n\n".join(results)

if __name__ == "__main__":
    target_ip = "192.168.1.1"
    output = run_sequence(target_ip)
    print(output)
