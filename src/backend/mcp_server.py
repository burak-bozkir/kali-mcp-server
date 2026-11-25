#!/usr/bin/env python3
"""
Kali MCP server (stdio). Exposes the Kali tools to an AI agent and forwards
every call over HTTP to kali_server.py (--server / KALI_API_SERVER). It never
runs a tool itself.

Some of the code here was inspired by https://github.com/whit3rabbit0/project_astro
"""

import argparse
import logging
import os
import sys
import time
from typing import Any, Dict, Optional

import requests
from mcp.server.fastmcp import FastMCP

# stdout carries the MCP JSON-RPC stream (stdio transport), so logs go to stderr
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stderr)])
logger = logging.getLogger(__name__)

DEFAULT_KALI_SERVER = os.environ.get("KALI_API_SERVER", "http://localhost:5001")  # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests
# Expose the execute_command tool only when asked (the server must also allow it)
DEFAULT_ENABLE_COMMAND = os.environ.get("KALI_ENABLE_COMMAND", "0").strip().lower() in ("1", "true", "yes", "y", "on")


class KaliToolsClient:
    """HTTP client for the Kali Tools API server."""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """One API call. Errors come back as {"error": ..., "success": False}."""
        url = f"{self.server_url}/{endpoint}"
        try:
            logger.debug(f"{method} {url} {kwargs}")
            response = requests.request(method, url, timeout=self.timeout, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Keep the server's own error message (e.g. validation errors) for the agent
            msg = str(e)
            try:
                body = e.response.json()
                if isinstance(body, dict) and body.get("error"):
                    msg = f"{e.response.status_code}: {body['error']}"
            except Exception:
                pass
            logger.error(f"Request failed: {msg}")
            return {"error": msg, "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return {"error": f"Request failed: {e}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {"error": f"Unexpected error: {e}", "success": False}

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("GET", endpoint, params=params or {})

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", endpoint, json=json_data)

    def execute_command(self, command: str) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command})

    # ---- long-running scans -------------------------------------------
    # Scans can take far longer than one MCP/HTTP request may stay open
    # (gobuster/nikto default to 30 min on the server). So tools start the scan
    # with "async": true, wait up to `self.timeout - 15` seconds, and if it is
    # still running return its scan_id — the scan keeps running on Kali and
    # the agent fetches the result later with scan_status(scan_id).
    FINAL_STATUSES = ("completed", "failed", "timeout", "cancelled")

    def run_scan(self, endpoint: str, data: Dict[str, Any], timeout: int = 0) -> Dict[str, Any]:
        body = dict(data)
        body["async"] = True
        if timeout and timeout > 0:
            body["timeout"] = int(timeout)
        started = self.safe_post(endpoint, body)
        if "error" in started or not started.get("scan_id") or not started.get("async"):
            return started      # validation error, or an old server that answered synchronously
        return self.wait_scan(started["scan_id"], max(30, self.timeout - 15))

    def wait_scan(self, scan_id: str, budget: float) -> Dict[str, Any]:
        t0 = time.time()
        while True:
            snap = self.safe_get(f"api/scans/{scan_id}", {"lines": 0})
            if "error" in snap:
                return snap
            if snap.get("status") in self.FINAL_STATUSES:
                return self.scan_result(snap)
            waited = time.time() - t0
            if waited >= budget:
                return {
                    "success": True, "status": "running", "scan_id": scan_id,
                    "command": snap.get("command"), "elapsed": snap.get("elapsed"),
                    "timeout": snap.get("timeout"), "progress": snap.get("progress"),
                    "message": (f"Still running on the Kali server (server-side timeout "
                                f"{snap.get('timeout')}s). Call scan_status('{scan_id}') later "
                                f"to get the output; scan_cancel('{scan_id}') stops it."),
                }
            time.sleep(min(1 if waited < 10 else 3, max(0.2, budget - waited)))

    def scan_result(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        """Final result of a finished scan: status, raw output and parsed findings."""
        out = {k: snap.get(k) for k in ("scan_id", "status", "command", "return_code",
                                        "timed_out", "elapsed", "timeout", "history_id")}
        out["success"] = snap.get("status") in ("completed", "timeout")
        if snap.get("status") == "timeout":
            out["note"] = "Timed out — output below is partial. Re-run with a larger timeout if needed."
        hid = snap.get("history_id")
        if hid:
            cmd = (self.safe_get(f"api/history/{hid}").get("command") or {})
            out["stdout"] = cmd.get("stdout", "")
            out["stderr"] = cmd.get("stderr", "")
            f = self.safe_get(f"api/history/{hid}/findings")
            if f.get("supported"):
                out["findings_summary"] = f.get("summary")
                out["findings"] = (f.get("findings") or [])[:30]
        return out

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")


def setup_mcp_server(kali_client: KaliToolsClient, enable_command: bool = False) -> FastMCP:
    """Register every tool on a FastMCP instance."""
    mcp = FastMCP("kali-mcp")
    
    run = kali_client.run_scan

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "", ports: str = "", additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/nmap", {"target": target, "scan_type": scan_type, "ports": ports,
                                      "additional_args": additional_args}, timeout)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/gobuster", {"url": url, "mode": mode, "wordlist": wordlist,
                                          "additional_args": additional_args}, timeout)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.

        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/dirb", {"url": url, "wordlist": wordlist, "additional_args": additional_args}, timeout)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.

        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/nikto", {"target": target, "additional_args": additional_args}, timeout)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.

        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/sqlmap", {"url": url, "data": data, "additional_args": additional_args}, timeout)

    @mcp.tool()
    def metasploit_run(module: str, options: Optional[Dict[str, Any]] = None, timeout: int = 0) -> Dict[str, Any]:
        """
        Execute a Metasploit module.

        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/metasploit", {"module": module, "options": options or {}}, timeout)

    @mcp.tool()
    def hydra_attack(target: str, service: str, username: str = "", username_file: str = "",
                     password: str = "", password_file: str = "", additional_args: str = "",
                     timeout: int = 0) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.

        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/hydra", {
            "target": target, "service": service, "username": username, "username_file": username_file,
            "password": password, "password_file": password_file, "additional_args": additional_args}, timeout)

    @mcp.tool()
    def john_crack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format_type: str = "",
                   additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.

        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/john", {"hash_file": hash_file, "wordlist": wordlist, "format": format_type,
                                      "additional_args": additional_args}, timeout)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.

        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/wpscan", {"url": url, "additional_args": additional_args}, timeout)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a", timeout: int = 0) -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.

        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            timeout: Max run time in seconds (0 = server default for this tool, e.g. gobuster/nikto 1800). Long scans return a scan_id; use scan_status.
        """
        return run("api/tools/enum4linux", {"target": target, "additional_args": additional_args}, timeout)

    @mcp.tool()
    def scan_status(scan_id: str, wait: int = 0) -> Dict[str, Any]:
        """
        Get the status/result of a scan started by any *_scan tool that returned
        status "running" (long gobuster/nikto/sqlmap/hydra runs keep going on the server).

        Args:
            scan_id: The scan_id returned by the tool
            wait: Seconds to wait for it to finish before answering (0 = answer now)

        Returns:
            While running: elapsed time, timeout and progress (gobuster reports %).
            When finished: status, stdout/stderr and parsed findings.
        """
        budget = min(max(0, wait), max(30, kali_client.timeout - 15))
        if budget:
            return kali_client.wait_scan(scan_id, budget)
        snap = kali_client.safe_get(f"api/scans/{scan_id}", {"lines": 0})
        if "error" in snap:
            return snap
        if snap.get("status") in kali_client.FINAL_STATUSES:
            return kali_client.scan_result(snap)
        return {k: snap.get(k) for k in ("scan_id", "status", "command", "elapsed",
                                         "timeout", "progress", "total_lines")}

    @mcp.tool()
    def scan_cancel(scan_id: str) -> Dict[str, Any]:
        """
        Stop a running scan (kills the whole process group on the Kali server).
        Output collected so far is saved to history.

        Args:
            scan_id: The scan_id returned by the tool
        """
        return kali_client.safe_post(f"api/scans/cancel/{scan_id}", {})

    def _compact_workflow(wf: Dict[str, Any], max_findings: int = 25) -> Dict[str, Any]:
        """Trim a workflow to what an AI agent needs (no raw stdout, top findings only)."""
        steps = [{k: s.get(k) for k in ("index", "tool", "target", "status", "note",
                                         "duration", "history_id", "summary")}
                 for s in wf.get("steps", [])]
        nmap = next((s for s in wf.get("steps", []) if s.get("tool") == "nmap"), {})
        return {
            "workflow_id": wf.get("id"),
            "target": wf.get("target"),
            "status": wf.get("status"),
            "error": wf.get("error") or None,
            "summary": wf.get("summary"),
            "open_ports": nmap.get("ports", []),
            "web_targets": wf.get("web_targets", []),
            "steps": steps,
            "top_findings": [{k: f.get(k) for k in ("severity", "tool", "source", "title", "detail")}
                             for f in (wf.get("findings") or [])[:max_findings]],
            "report_pdf": f"{kali_client.server_url}/api/workflows/{wf.get('id')}/report",
        }

    @mcp.tool()
    def recon_workflow(
        target: str,
        run_gobuster: bool = True,
        run_nikto: bool = True,
        nmap_args: str = "-T4 -Pn",
        ports: str = "",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        max_web_targets: int = 5,
        step_timeout: int = 0,
        wait: bool = True,
        max_wait: int = 0,
    ) -> Dict[str, Any]:
        """
        Run a chained recon workflow on ONE host: nmap -sV first, then gobuster
        and/or nikto automatically on every web port nmap discovers
        (http/https, e.g. 80, 443, 8080). Use this instead of calling nmap,
        gobuster and nikto one by one. Only scan hosts you are authorized to test.

        Args:
            target: A single IP or hostname (no URL, no CIDR), e.g. 10.0.0.5
            run_gobuster: Run gobuster dir on each web port
            run_nikto: Run nikto on each web port
            nmap_args: Extra nmap arguments (scan type is -sV)
            ports: Optional nmap port spec, e.g. "1-1000,8080"
            wordlist: Wordlist for gobuster
            max_web_targets: Max number of web ports to follow up (1-20)
            step_timeout: Timeout per step in seconds (0 = each tool's server default,
                e.g. nmap 900, gobuster/nikto 1800)
            wait: If True, block until the workflow finishes (or max_wait passes)
            max_wait: Seconds to wait when wait=True (0 = client timeout minus a margin)

        Returns:
            Compact result: status, open ports, web targets, per-step summary and
            the most severe findings. If still running, call recon_status later.
        """
        data = {
            "target": target, "run_gobuster": run_gobuster, "run_nikto": run_nikto,
            "nmap_args": nmap_args, "ports": ports, "wordlist": wordlist,
            "max_web_targets": max_web_targets,
        }
        if step_timeout and step_timeout > 0:
            data["step_timeout"] = step_timeout
        started = kali_client.safe_post("api/workflows/recon", data)
        if "error" in started:
            return started
        wf_id = started.get("workflow_id")
        if not wait:
            return {"workflow_id": wf_id, "status": "running",
                    "message": "Workflow started. Poll with recon_status(workflow_id)."}

        budget = max_wait if max_wait > 0 else max(30, kali_client.timeout - 15)
        deadline = time.time() + budget
        wf = started.get("workflow", {})
        while time.time() < deadline:
            time.sleep(3)
            res = kali_client.safe_get(f"api/workflows/{wf_id}")
            if "error" in res:
                continue
            wf = res.get("workflow", wf)
            if wf.get("status") != "running":
                break
        out = _compact_workflow(wf)
        if out["status"] == "running":
            out["message"] = (f"Still running after {budget}s. "
                              f"Call recon_status('{wf_id}') to get the final result.")
        return out

    @mcp.tool()
    def recon_status(workflow_id: str) -> Dict[str, Any]:
        """
        Get the current state of a chained recon workflow started with recon_workflow.

        Args:
            workflow_id: The ID returned by recon_workflow

        Returns:
            Compact workflow result (status, steps, web targets, top findings)
        """
        res = kali_client.safe_get(f"api/workflows/{workflow_id}")
        if "error" in res:
            return res
        return _compact_workflow(res.get("workflow", {}))

    @mcp.tool()
    def recon_cancel(workflow_id: str) -> Dict[str, Any]:
        """
        Cancel a running recon workflow (stops the current step, skips the rest).

        Args:
            workflow_id: The ID returned by recon_workflow
        """
        return kali_client.safe_post(f"api/workflows/{workflow_id}/cancel", {})

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """Check the health status of the Kali API server (which tools are installed)."""
        return kali_client.check_health()

    if not enable_command:
        return mcp

    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.

        Args:
            command: The command to execute
        """
        return kali_client.execute_command(command)

    return mcp


def parse_args():
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER,
                        help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--enable-command", action="store_true", default=DEFAULT_ENABLE_COMMAND,
                        help="Expose the execute_command tool (server needs KALI_ENABLE_COMMAND=1 too)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    kali_client = KaliToolsClient(args.server, args.timeout)
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Connected to Kali API server at {args.server} (status: {health['status']})")
        missing = [tool for tool, ok in health.get("tools_status", {}).items() if not ok]
        if not health.get("all_essential_tools_available", False) and missing:
            logger.warning(f"Missing tools on the Kali server: {', '.join(missing)}")

    mcp = setup_mcp_server(kali_client, enable_command=args.enable_command)
    logger.info("Starting Kali MCP server")
    mcp.run()


if __name__ == "__main__":
    main()
