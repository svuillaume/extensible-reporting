import os
import json
from dotenv import load_dotenv
from laceworksdk import LaceworkClient
from jinja2 import Environment, FileSystemLoader
import datetime
cd

def load_environment_variables():
    """Load environment variables from .env file."""
    load_dotenv(".env")
    start_time = os.getenv("start_time")
    end_time = os.getenv("end_time")

    if not start_time or not end_time:
        raise RuntimeError("start_time / end_time not loaded from .env")
    
    return start_time, end_time


def initialize_lacework_client():
    """Initialize and return the Lacework client."""
    return LaceworkClient(
        account="2218177.lacework.net",
        api_key="22181775_F83E8DB411871C17666943C410F2732F5DF43AE0F6696BF",
        api_secret="_5cd40cd6de5c6985acc7e9becdad2069"
    )


def fetch_data(lw_client, start_time, end_time):
    """Fetch events, host vulnerabilities, and container vulnerabilities."""
    events = lw_client.events.search(json={
        "timeFilter": {"startTime": start_time, "endTime": end_time}
    })
    host_vulns = lw_client.vulnerabilities.hosts.search(json={
        "timeFilter": {"startTime": start_time, "endTime": end_time},
        "severityFilter": {"minSeverity": "CRITICAL"},
        "vulnerabilityimpactFilter": {"minImpact": "CRITICAL"}
    })
    container_vulns = lw_client.vulnerabilities.containers.search(json={
        "timeFilter": {"startTime": start_time, "endTime": end_time},
        "filters": [
            {
                "field": "imageId",
                "expression": "eq",
                "value": "sha256:657922eb2d64b0a34fe7339f8b48afb9f2f44635d7d6eaa92af69591d29b3330"
            }
        ]
    })

    return list(events), list(host_vulns), list(container_vulns)


def save_report(data, filename="report.json"):
    """Save the report data to a JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Report saved to {filename}")


def save_report_html(data, filename="report.html", template_name="csa_report.jinja2"):
    """Render report data to an HTML file using a Jinja2 template.

    The template is expected to be in the 'templates' directory next to this module.
    The template will receive a single variable named 'report' containing the full report dict.
    """
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir))

    try:
        template = env.get_template(template_name)
        html = template.render(report=data)
    except Exception:
        # If template loading/rendering fails, fall back to a simple preformatted JSON view
        html = "<html><head><meta charset=\"utf-8\"></head><body><h1>Report</h1><pre>{}</pre></body></html>".format(
            json.dumps(data, indent=2)
        )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"HTML report saved to {filename}")


def main():
    start_time, end_time = load_environment_variables()
    lw_client = initialize_lacework_client()
    events, host_vulns, container_vulns = fetch_data(lw_client, start_time, end_time)

    report_data = {
        "timeWindow": {"start": start_time, "end": end_time},
        "events": events,
        "host_vulnerabilities": host_vulns,
        "container_vulnerabilities": container_vulns
    }

    save_report(report_data)
    save_report_html(report_data, filename="report.html")


if __name__ == "__main__":
    main()
