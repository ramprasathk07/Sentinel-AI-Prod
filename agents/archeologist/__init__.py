"""
Archeologist agent package.

Re-exports ``root_agent`` so the Google ADK CLI can discover it:
    adk run archeologist
    adk web
"""

from agents.archeologist.agent import root_agent

__all__ = ["root_agent"]
