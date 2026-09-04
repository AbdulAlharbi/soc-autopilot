from socpilot.commander import load_scenario
from socpilot.models import Incident


def make_incident(settings, scenario: str = "beacon-c2-workstation") -> Incident:
    alert, _ = load_scenario(settings.scenarios_dir / f"{scenario}.json")
    return Incident(alert=alert)
