import subprocess
import time

PYTHON = "/opt/project/ghostTrap/venv/bin/python"
ROOT = "/opt/project/ghostTrap"

def run_module(module_name):
    print(f"[worker] running {module_name}", flush=True)
    result = subprocess.run(
        [PYTHON, "-m", module_name],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(result.stdout, flush=True)

    if result.stderr:
        print(result.stderr, flush=True)

    if result.returncode != 0:
        print(f"[worker] {module_name} exited with {result.returncode}", flush=True)

print("[worker] ReputationWatch worker started", flush=True)

last_external = 0
last_abuse = 0

while True:
    now = time.time()

    run_module("reputationwatch.sync_commands")

    if now - last_external >= 300:
        run_module("reputationwatch.sync_external_intel")
        last_external = now

    if now - last_abuse >= 900:
        run_module("reputationwatch.sync_abuseipdb")
        last_abuse = now

    time.sleep(10)
