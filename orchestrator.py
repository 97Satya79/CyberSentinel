import os
import sys
import time
import requests

def generate_yaml_plan(target_url: str, output_file: str = "scan_plan.yaml") -> str:
    """
    Generates a YAML scan plan configuration for the spider, passiveScan-wait,
    and activeScan jobs and saves it to the specified file in the same directory.
    """
    yaml_content = f"""env:
  contexts:
    - name: "Module1-Prototype"
      urls:
        - "{target_url}"
      includePaths:
        - "{target_url}/.*"
jobs:
  - type: spider
  - type: passiveScan-wait
  - type: activeScan
    parameters:
      maxDuration: 5  # Limits active scan to 5 minutes so it doesn't run forever
"""
    # Resolve file path to the directory containing this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, output_file)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(yaml_content)

    print(f"Scan plan successfully generated and saved to: {file_path}")
    return file_path


def trigger_zap_scan(file_path: str, zap_base_url: str = "http://127.0.0.1:8080"):
    """
    Sends an HTTP GET request to the ZAP API to execute the automation plan.
    Returns the JSON response containing the planId.
    """
    zap_url = f"{zap_base_url}/JSON/automation/action/runPlan/"
    params = {"filePath": file_path}

    try:
        response = requests.get(zap_url, params=params)
        response_json = response.json()
        print(f"ZAP API Response: {response_json}")
        return response_json
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with ZAP API: {e}")
        return None


def poll_plan_progress(
    plan_id: str | int,
    zap_base_url: str = "http://127.0.0.1:8080",
    poll_interval: int = 5,
    timeout: int = 360,
) -> dict:
    """
    Polls ZAP's planProgress endpoint at regular intervals until the
    automation plan completes or the timeout is reached. Tracks both
    spider and active scan progress.

    :param plan_id: The ID of the running automation plan.
    :param zap_base_url: Base URL of the ZAP API daemon.
    :param poll_interval: Polling frequency in seconds (default: 5s).
    :param timeout: Maximum seconds to wait before terminating the polling loop (default: 360s).
    :return: The final plan progress dictionary from ZAP API.
    """
    progress_url = f"{zap_base_url}/JSON/automation/view/planProgress/"
    spider_scans_url = f"{zap_base_url}/JSON/spider/view/scans/"
    ascan_scans_url = f"{zap_base_url}/JSON/ascan/view/scans/"
    stop_url = f"{zap_base_url}/JSON/automation/action/stopPlan/"

    # Record existing scans count before this scan starts to accurately track progress
    try:
        initial_spider_count = len(requests.get(spider_scans_url).json().get("scans", []))
    except Exception:
        initial_spider_count = 0

    try:
        initial_ascan_count = len(requests.get(ascan_scans_url).json().get("scans", []))
    except Exception:
        initial_ascan_count = 0

    start_time = time.time()
    print(f"\n[+] Monitoring Plan ID: {plan_id} (polling every {poll_interval}s, timeout {timeout}s)...")

    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            print(f"[!] Plan {plan_id} timed out after {int(elapsed)} seconds. Halting plan...")
            try:
                requests.get(stop_url, params={"planId": plan_id})
            except requests.exceptions.RequestException as e:
                print(f"[!] Failed to stop plan {plan_id}: {e}")
            raise TimeoutError(f"Automation plan {plan_id} exceeded maximum timeout of {timeout} seconds.")

        try:
            resp = requests.get(progress_url, params={"planId": plan_id})
            progress_data = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"[!] Warning: Network error communicating with ZAP: {e}")
            time.sleep(poll_interval)
            continue

        finished = progress_data.get("finished")

        # Determine Spider progress
        spider_pct = 0
        try:
            spiders = requests.get(spider_scans_url).json().get("scans", [])
            if finished:
                spider_pct = 100
            elif len(spiders) > initial_spider_count:
                spider_pct = int(spiders[-1].get("progress", 0))
        except Exception:
            if finished:
                spider_pct = 100

        # Determine Active Scan progress
        ascan_pct = 0
        try:
            ascans = requests.get(ascan_scans_url).json().get("scans", [])
            if finished:
                ascan_pct = 100
            elif len(ascans) > initial_ascan_count:
                ascan_pct = int(ascans[-1].get("progress", 0))
        except Exception:
            if finished:
                ascan_pct = 100

        # Check which job is currently executing
        jobs = progress_data.get("jobs", [])
        running_jobs = [j.get("type", j.get("name")) for j in jobs if j.get("status") == "running"]
        current_job = running_jobs[0] if running_jobs else ("completed" if finished else "processing")

        print(
            f"[Progress] Plan ID: {plan_id} | Elapsed: {int(elapsed)}s | "
            f"Job: {current_job} | Spider: {spider_pct}% | ActiveScan: {ascan_pct}%"
        )

        # Check if the automation plan reports completion
        if finished:
            print(f"\n[✓] Automation Plan {plan_id} completed successfully at {finished}!")
            errors = progress_data.get("error", [])
            if errors:
                print("[!] Errors encountered during scan:")
                for err in errors:
                    print(f"    - {err}")

            info_messages = progress_data.get("info", [])
            if info_messages:
                print("[*] Execution Summary:")
                for msg in info_messages:
                    print(f"    - {msg}")
            return progress_data

        time.sleep(poll_interval)


def harvest_alerts(target_url: str, zap_base_url: str = "http://127.0.0.1:8080"):
    """
    Retrieves and prints the alerts identified by ZAP for the specified target URL.
    """
    alerts_url = f"{zap_base_url}/JSON/core/view/alerts/"
    params = {"baseurl": target_url}

    try:
        response = requests.get(alerts_url, params=params)
        response_json = response.json()
        alerts = response_json.get("alerts", [])

        print(f"\n[+] Harvesting alerts for {target_url} ({len(alerts)} found)...")
        for alert in alerts:
            risk = alert.get("risk", "Unknown")
            name = alert.get("alert") or alert.get("name", "Unknown Alert")
            url = alert.get("url", "")
            print(f"[{risk}] {name} - {url}")

        return alerts
    except requests.exceptions.RequestException as e:
        print(f"[!] Error retrieving alerts from ZAP: {e}")
        return []


if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    plan_path = generate_yaml_plan(target_url)
    scan_response = trigger_zap_scan(plan_path)

    if scan_response and "planId" in scan_response:
        plan_id = scan_response["planId"]
        poll_plan_progress(plan_id, poll_interval=5, timeout=360)
        harvest_alerts(target_url)
    else:
        print("[!] Unable to trigger scan or missing planId in response.")
