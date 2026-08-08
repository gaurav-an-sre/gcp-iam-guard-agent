"""IAM Guard: an ADK workflow agent that audits GCP IAM for abuse paths."""

from iam_guard.agent import root_agent

__all__ = ["root_agent"]
__version__ = "0.1.0"
