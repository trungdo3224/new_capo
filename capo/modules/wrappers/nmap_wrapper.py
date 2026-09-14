"""Nmap wrapper with XML parsing and state integration."""

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from capo.modules.wrappers.base import BaseWrapper
from capo.state import state_manager
from capo.utils.display import (
    print_info,
    print_ports_table,
    print_success,
    print_warning,
)


class NmapWrapper(BaseWrapper):
    tool_name = "nmap"
    binary_name = "nmap"

    def quick_scan(self, target: str | None = None):
        """Fast all-ports TCP scan (-p- --min-rate)."""
        target = self._resolve_target(target)
        out = self._output_file("quick")
        xml_out = out.with_suffix(".xml")

        rate = self.profile_config["nmap_rate"]
        timing = self.profile_config["nmap_timing"]

        cmd = [
            "nmap", "-Pn", "-p-", "--open",
            "--min-rate", str(rate),
            "--stats-every", "15s",
            timing,
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def detailed_scan(self, ports: str | None = None, target: str | None = None):
        """Detailed scan with -sC -sV on discovered ports."""
        target = self._resolve_target(target)
        if ports is None:
            open_ports = state_manager.get_open_ports()
            if not open_ports:
                print_warning("No open ports in state. Run quick scan first: capo scan quick")
                return
            ports = ",".join(str(p) for p in open_ports)

        out = self._output_file("detailed")
        xml_out = out.with_suffix(".xml")
        timing = self.profile_config["nmap_timing"]

        cmd = [
            "nmap", "-Pn", "-sC", "-sV",
            "-p", ports,
            "--stats-every", "15s",
            timing,
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def udp_scan(self, target: str | None = None):
        """UDP top ports scan."""
        target = self._resolve_target(target)
        out = self._output_file("udp")
        xml_out = out.with_suffix(".xml")
        timing = self.profile_config["nmap_timing"]

        cmd = [
            "nmap", "-Pn", "-sU",
            "--top-ports", "50",
            "--open",
            "--stats-every", "15s",
            timing,
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def vuln_scan(self, ports: str | None = None, target: str | None = None):
        """Run vuln NSE scripts (OSCP-safe)."""
        target = self._resolve_target(target)
        if ports is None:
            open_ports = state_manager.get_open_ports()
            if not open_ports:
                print_warning("No open ports in state.")
                return
            ports = ",".join(str(p) for p in open_ports)

        out = self._output_file("vuln")
        xml_out = out.with_suffix(".xml")

        cmd = [
            "nmap", "-Pn", "--script", "vuln",
            "-p", ports,
            "--stats-every", "15s",
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def parse_output(self, result: subprocess.CompletedProcess, output_file: Path | None):
        """Parse Nmap XML output and update state."""
        if output_file is None:
            return

        # Find the corresponding XML file
        xml_file = output_file.with_suffix(".xml")
        # Also check if the raw output file's stem leads to an xml
        base = output_file.with_suffix("")
        possible_xml = base.with_suffix(".xml")
        if possible_xml.exists():
            xml_file = possible_xml

        if not xml_file.exists():
            # Try to find any xml file nearby with same prefix
            parent = output_file.parent
            prefix = output_file.stem.rsplit("_", 1)[0] if "_" in output_file.stem else output_file.stem
            for f in parent.glob(f"{prefix}*.xml"):
                xml_file = f
                break

        if not xml_file.exists():
            print_warning("No XML output found to parse. State not updated from this scan.")
            return

        self._parse_xml(xml_file)

    def _parse_xml(self, xml_path: Path):
        """Parse Nmap XML and update state.

        Extracts ports, services, versions, CPE, NSE script output,
        and auto-enriches state from well-known scripts.
        """
        try:
            tree = ET.parse(xml_path)  # noqa: S314
        except ET.ParseError:
            print_warning(f"Failed to parse XML: {xml_path}")
            return

        root = tree.getroot()
        port_count = 0
        nse_count = 0
        vuln_count = 0

        for host in root.findall(".//host"):
            # Extract OS info
            os_match = host.find(".//osmatch")
            if os_match is not None:
                os_name = os_match.get("name", "")
                if os_name:
                    state_manager.set("os", os_name)

            # Extract hostname
            hostname_el = host.find(".//hostname")
            if hostname_el is not None:
                hostname = hostname_el.get("name", "")
                if hostname:
                    state_manager.set("hostname", hostname)

            # Extract ports
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue

                port_state = state_el.get("state", "")
                if port_state != "open":
                    continue

                portid = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                service_name = ""
                version = ""
                cpe_list = []
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    ver = service_el.get("version", "")
                    extra = service_el.get("extrainfo", "")
                    version = " ".join(filter(None, [product, ver, extra]))

                    # Extract CPE identifiers
                    for cpe_el in service_el.findall("cpe"):
                        if cpe_el.text:
                            cpe_list.append(cpe_el.text)

                # Preserve better service name when -sV returns "tcpwrapped"
                existing_ports = state_manager.get("ports", [])
                existing = next(
                    (p for p in existing_ports
                     if p.get("port") == portid and p.get("protocol") == protocol),
                    None,
                )
                if (service_name in ("tcpwrapped", "")
                        and existing
                        and existing.get("service", "") not in ("tcpwrapped", "")):
                    service_name = existing["service"]

                state_manager.add_port(portid, protocol, service_name, version, port_state)
                port_count += 1

                # Store CPE in banners
                if cpe_list:
                    state_manager.update_banner(portid, protocol, cpe=cpe_list)

                # Extract per-port NSE scripts
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    script_output = script_el.get("output", "")
                    if script_id:
                        state_manager.add_nse_result(portid, script_id, script_output, protocol)
                        nse_count += 1
                        # Auto-enrich from well-known scripts
                        vuln_count += self._enrich_from_nse(
                            portid, protocol, script_id, script_output, script_el,
                        )

            # Extract host-level NSE scripts (<hostscript>)
            for hostscript in host.findall(".//hostscript/script"):
                script_id = hostscript.get("id", "")
                script_output = hostscript.get("output", "")
                if script_id:
                    state_manager.add_nse_result(0, script_id, script_output)
                    nse_count += 1
                    vuln_count += self._enrich_from_nse(
                        0, "tcp", script_id, script_output, hostscript,
                    )

        print_success(f"Parsed {port_count} open port(s) from Nmap XML.")
        if nse_count:
            print_info(f"Extracted {nse_count} NSE script result(s).")
        if vuln_count:
            print_warning(
                f"Discovered {vuln_count} vulnerability(s) from NSE scripts."
            )
        ports = state_manager.get("ports", [])
        if ports:
            print_ports_table(ports)

    # ------------------------------------------------------------------
    # Auto-enrichment from well-known NSE scripts
    # ------------------------------------------------------------------

    def _enrich_from_nse(self, port: int, protocol: str, script_id: str,
                         output: str, script_el: ET.Element) -> int:
        """Interpret well-known NSE scripts and enrich state.

        Returns the number of vulnerabilities added.
        """
        vuln_count = 0

        # --- smb-vuln-* / vuln-* scripts ---
        if script_id.startswith(("smb-vuln-", "vuln-")):
            vuln_count += self._parse_vuln_script(port, script_id, output)

        # --- http-title ---
        elif script_id == "http-title":
            title = output.strip()
            if title:
                state_manager.update_banner(port, protocol, http_title=title)

        # --- http-server-header ---
        elif script_id == "http-server-header":
            header = output.strip()
            if header:
                state_manager.update_banner(port, protocol, server_header=header)

        # --- ssl-cert: extract CN and SANs for vhost/domain auto-discovery ---
        elif script_id == "ssl-cert":
            self._enrich_ssl_cert(output, script_el)

        # --- ldap-rootdse: extract domain from namingContexts ---
        elif script_id == "ldap-rootdse":
            self._enrich_ldap_rootdse(output)

        # --- smb-os-discovery: OS, domain, hostname ---
        elif script_id == "smb-os-discovery":
            self._enrich_smb_os_discovery(output)

        # --- smb2-security-mode: signing info ---
        elif script_id == "smb2-security-mode":
            state_manager.update_banner(port, protocol, smb_signing=output.strip())

        # --- ftp-anon: anonymous FTP ---
        elif script_id == "ftp-anon":
            if "Anonymous FTP login allowed" in output:
                state_manager.update_banner(port, protocol, ftp_anon=True)

        # --- ssh-hostkey / ssh2-enum-algos: store banner ---
        elif script_id in ("ssh-hostkey", "ssh2-enum-algos"):
            key = script_id.replace("-", "_")
            state_manager.update_banner(port, protocol, **{key: output.strip()})

        return vuln_count

    def _parse_vuln_script(self, port: int, script_id: str, output: str) -> int:
        """Parse smb-vuln-* and vuln-* script output for confirmed vulnerabilities."""
        vuln_count = 0
        # Nmap vuln scripts report "State: VULNERABLE" for confirmed findings
        if "VULNERABLE" not in output.upper():
            return 0

        # Extract CVE IDs if present
        cve_pattern = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
        refs = cve_pattern.findall(output)

        # Extract title from output (typically first non-empty line)
        lines = [ln.strip() for ln in output.strip().splitlines() if ln.strip()]
        title = lines[0] if lines else script_id

        # Determine state
        vuln_state = "VULNERABLE"
        if "LIKELY VULNERABLE" in output.upper():
            vuln_state = "LIKELY VULNERABLE"

        state_manager.add_vulnerability(
            vuln_id=refs[0] if refs else script_id,
            title=title,
            port=port,
            script=script_id,
            state=vuln_state,
            refs=refs,
        )
        vuln_count += 1
        return vuln_count

    def _enrich_ssl_cert(self, output: str, script_el: ET.Element):
        """Extract CN and SANs from ssl-cert output and add as vhosts/domains."""
        discovered = set()

        # Try structured <table> elements first (more reliable)
        for table in script_el.findall(".//table"):
            key = table.get("key", "")
            if key == "subject":
                for elem in table.findall("elem"):
                    if elem.get("key") == "commonName" and elem.text:
                        discovered.add(elem.text.strip())
            elif key == "extensions":
                for ext_table in table.findall("table"):
                    if ext_table.get("key") == "":
                        name_el = ext_table.find("elem[@key='name']")
                        val_el = ext_table.find("elem[@key='value']")
                        if name_el is not None and val_el is not None:
                            if "Subject Alternative Name" in (name_el.text or ""):
                                for name in re.findall(r"DNS:([^\s,]+)", val_el.text or ""):
                                    discovered.add(name)

        # Fallback: parse text output
        if not discovered:
            cn_match = re.search(r"commonName=([^\s/,]+)", output)
            if cn_match:
                discovered.add(cn_match.group(1))
            for san in re.findall(r"DNS:([^\s,]+)", output):
                discovered.add(san)

        for name in discovered:
            # Skip wildcard and IP-like entries
            if name.startswith("*") or re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                continue
            state_manager.add_vhost(name)
            # If it looks like a domain (has dots, not just hostname)
            if "." in name:
                state_manager.add_domain(name)

        if discovered:
            names = ", ".join(sorted(discovered))
            print_info(f"SSL cert: discovered {len(discovered)} name(s): {names}")

    def _enrich_ldap_rootdse(self, output: str):
        """Extract domain from ldap-rootdse namingContexts."""
        # Look for DC=xxx,DC=yyy pattern
        dc_match = re.search(r"(DC=[^,\s]+(?:,DC=[^,\s]+)+)", output, re.IGNORECASE)
        if dc_match:
            dc_parts = re.findall(r"DC=([^,\s]+)", dc_match.group(1), re.IGNORECASE)
            if dc_parts:
                domain = ".".join(dc_parts)
                state_manager.add_domain(domain)
                print_info(f"LDAP rootDSE: auto-discovered domain '{domain}'")

                # Update domain_info
                di = state_manager.get("domain_info", {})
                if not di.get("domain_name"):
                    di["domain_name"] = domain
                    state_manager.set("domain_info", di)

    def _enrich_smb_os_discovery(self, output: str):
        """Extract OS, domain, hostname from smb-os-discovery."""
        # Normalize literal \n to actual newlines for consistent parsing
        text = output.replace("\\n", "\n")

        # OS: Windows Server 2016 Standard 14393
        os_match = re.search(r"OS:\s*(.+)", text)
        if os_match:
            os_name = os_match.group(1).strip()
            if os_name:
                state_manager.set("os", os_name)

        # Computer name: FOREST
        comp_match = re.search(r"Computer name:\s*(\S+)", text)
        if comp_match:
            state_manager.set("hostname", comp_match.group(1).strip())

        # Domain name: htb.local
        domain_match = re.search(r"Domain name:\s*(\S+)", text)
        if domain_match:
            domain = domain_match.group(1).strip()
            if domain and domain.lower() != "workgroup":
                state_manager.add_domain(domain)
                print_info(f"SMB discovery: auto-discovered domain '{domain}'")

        # FQDN: FOREST.htb.local
        fqdn_match = re.search(r"FQDN:\s*(\S+)", text)
        if fqdn_match:
            fqdn = fqdn_match.group(1).strip()
            if fqdn and "." in fqdn:
                state_manager.add_vhost(fqdn)

    def custom_scan(self, extra_args: str, target: str | None = None):
        """Run a custom nmap scan with user-supplied flags. XML output is still parsed into state."""
        import shlex as _shlex
        target = self._resolve_target(target)
        out = self._output_file("custom")
        xml_out = out.with_suffix(".xml")

        try:
            parsed_args = _shlex.split(extra_args)
        except ValueError as e:
            print_warning(f"Invalid nmap args: {e}")
            return

        # Remove any existing -oX/-oN flags the user may have added to avoid conflicts
        filtered = []
        skip_next = False
        for tok in parsed_args:
            if skip_next:
                skip_next = False
                continue
            if tok in ("-oX", "-oN", "-oA", "-oG", "-oS"):
                skip_next = True
                continue
            # Also handle combined form like -oX<file>
            if any(tok.startswith(f) for f in ("-oX", "-oN", "-oA", "-oG", "-oS")):
                continue
            filtered.append(tok)

        # Remove target if user accidentally included it (we append it ourselves)
        if filtered and filtered[-1] == target:
            filtered = filtered[:-1]

        # Add --stats-every unless the user already included it
        if "--stats-every" not in filtered:
            filtered = ["--stats-every", "15s"] + filtered

        cmd = [
            "nmap", "-Pn",
            *filtered,
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def ports_scan(self, ports: str, target: str | None = None,
                   run_scripts: bool = True, detect_versions: bool = True):
        """Scan a specific port list with optional version/script detection."""
        target = self._resolve_target(target)
        out = self._output_file("ports")
        xml_out = out.with_suffix(".xml")
        timing = self.profile_config["nmap_timing"]

        flags = ["-Pn"]
        if run_scripts:
            flags.append("-sC")
        if detect_versions:
            flags.append("-sV")

        cmd = [
            "nmap", *flags,
            "-p", ports,
            "--stats-every", "15s",
            timing,
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def os_scan(self, target: str | None = None):
        """OS detection scan (-O). Best run as root."""
        target = self._resolve_target(target)
        out = self._output_file("os")
        xml_out = out.with_suffix(".xml")
        timing = self.profile_config["nmap_timing"]

        cmd = [
            "nmap", "-Pn", "-O", "--osscan-guess",
            "--stats-every", "15s",
            timing,
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def scripts_scan(self, scripts: str, ports: str | None = None, target: str | None = None):
        """Run specific NSE scripts. Falls back to all open ports if none supplied."""
        target = self._resolve_target(target)
        if ports is None:
            open_ports = state_manager.get_open_ports()
            if not open_ports:
                print_warning("No open ports in state. Specify --ports or run quick scan first.")
                return
            ports = ",".join(str(p) for p in open_ports)

        out = self._output_file("scripts")
        xml_out = out.with_suffix(".xml")

        cmd = [
            "nmap", "-Pn",
            "--script", scripts,
            "-p", ports,
            "--stats-every", "15s",
            "-oX", str(xml_out),
            "-oN", str(out.with_suffix(".nmap")),
            target,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    def get_suggestions(self) -> list[tuple[str, str]]:
        """Return suggestions based on discovered services."""
        suggestions = []
        services = state_manager.get_services_summary()

        port_service_hints = {
            21: ("FTP detected", "capo query ftp"),
            22: ("SSH detected", "capo query ssh"),
            25: ("SMTP detected", "capo query smtp"),
            53: ("DNS detected", "capo query dns"),
            80: ("HTTP detected - Run web fuzzing", "capo web fuzz"),
            88: ("Kerberos detected - AD environment!", "capo query kerberos"),
            110: ("POP3 detected", "capo query pop3"),
            111: ("RPCbind detected", "capo query rpc"),
            135: ("MSRPC detected - Windows host", "capo query msrpc"),
            139: ("NetBIOS-SSN detected", "capo nxc enum"),
            389: ("LDAP detected - AD environment!", "capo query ldap"),
            443: ("HTTPS detected - Run web fuzzing", "capo web fuzz --port 443 --https"),
            445: ("SMB detected - Enumerate shares", "capo nxc enum"),
            1433: ("MSSQL detected", "capo query mssql"),
            1521: ("Oracle detected", "capo query oracle"),
            3306: ("MySQL detected", "capo query mysql"),
            3389: ("RDP detected", "capo query rdp"),
            5432: ("PostgreSQL detected", "capo query postgres"),
            5985: ("WinRM detected", "capo query winrm"),
            8080: ("HTTP-Proxy/Alt-HTTP detected", "capo web fuzz --port 8080"),
            8443: ("HTTPS-Alt detected", "capo web fuzz --port 8443 --https"),
        }

        for port, service in services.items():
            if port in port_service_hints:
                title, cmd = port_service_hints[port]
                suggestions.append((f"Port {port}: {title}", cmd))

        return suggestions
