import csv
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import requests

from soc_core import (
    AZURE_CLI_CLIENT_ID,
    CLIENT_ID,
    DEFAULT_SENTINEL_WORKSPACE_ID,
    ENTRA_ERRORS,
    GRAPH_SCOPES,
    GraphRateLimitError,
    IP_CACHE,
    IPV4_REGEX,
    LOG_ANALYTICS_SCOPES,
    check_abuseipdb,
    check_intigriti_ip,
    export_ipsearcher_blocklist_and_csv,
    export_ipsearcher_html,
    export_sentinel_html,
    export_signins_html,
    extract_workspace_guid,
    fetch_signins_from_sentinel,
    get_output_dir,
    get_access_token,
    graph_get_with_retry,
    is_public_ip,
    resolve_targets_to_upns,
)

class _MessageBox:
    @staticmethod
    def showinfo(*args, **kwargs):
        return None

    @staticmethod
    def showwarning(*args, **kwargs):
        return None

    @staticmethod
    def showerror(*args, **kwargs):
        return None

    @staticmethod
    def askyesno(*args, **kwargs):
        return False

messagebox = _MessageBox()


class SOCWorkers:
    def get_active_sentinel_workspace_guid(self):
        """Returns a valid Sentinel Workspace GUID from config or the Sentinel tab selector."""
        ws_guid = extract_workspace_guid(DEFAULT_SENTINEL_WORKSPACE_ID)
        if not ws_guid and hasattr(self, "combo_workspace"):
            ws_guid = extract_workspace_guid(self.combo_workspace.get())
        return ws_guid

    # ---------------------------------------------------------------------
    # TAB 1: User Sign-ins Audit (UPN or AD SID, Single vs Bulk Mode)
    # ---------------------------------------------------------------------

    def worker_scan_risky(self, selected_level, updated_days):
        try:
            self.lbl_status_risky.configure(text="Authenticating via Microsoft Graph...")
            self.prog_risky.set(0.15)
            token = get_access_token(self.log_risky, scopes=GRAPH_SCOPES, client_id=CLIENT_ID)

            level_filter = ""
            if selected_level != "All":
                level_filter = f"riskLevel eq '{selected_level.lower()}' and "

            odata_filter = f"{level_filter}riskState eq 'atRisk'"
            self.lbl_status_risky.configure(text=f"Querying riskyUsers ({selected_level})...")
            self.log_risky(f"[*] Querying Entra ID Protection | Filter: {odata_filter}", "info")
            if updated_days > 0:
                self.log_risky(f"[*] Filtering accounts updated within the last {updated_days} day(s)...", "info")

            self.prog_risky.set(0.4)
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            url = f"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter={odata_filter}&$top=100"

            raw_risky_users = []
            while url:
                resp = graph_get_with_retry(url, headers, self.log_risky, allow_404=True)
                if resp.status_code == 404:
                    url = f"https://graph.microsoft.com/v1.0/riskyUsers?$filter={odata_filter}&$top=100"
                    resp = graph_get_with_retry(url, headers, self.log_risky)

                data = resp.json()
                raw_risky_users.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                if url:
                    time.sleep(0.3)

            filtered_users = []
            cutoff_dt = datetime.now(timezone.utc) - timedelta(days=updated_days) if updated_days > 0 else None

            for u in raw_risky_users:
                if cutoff_dt is not None:
                    last_upd_str = u.get("riskLastUpdatedDateTime")
                    if last_upd_str:
                        try:
                            clean_ts = last_upd_str.replace("Z", "+00:00")
                            upd_dt = datetime.fromisoformat(clean_ts)
                            if upd_dt < cutoff_dt:
                                continue
                        except ValueError:
                            pass
                filtered_users.append(u)

            self.prog_risky.set(1.0)

            if not filtered_users:
                time_msg = f" in the last {updated_days} day(s)" if updated_days > 0 else ""
                self.log_risky(
                    f"\n[+] CLEAN RESULT: No active Risky Users (Level: {selected_level}) found{time_msg}.",
                    "success"
                )
                self.lbl_status_risky.configure(text=f"Scan completed: 0 {selected_level}-risk users found.")
                messagebox.showinfo("Risky Users", f"No active {selected_level}-risk users found{time_msg}.")
                return

            self.discovered_risky_users = [
                u.get("userPrincipalName", "").strip().lower()
                for u in filtered_users if u.get("userPrincipalName")
            ]

            self.log_risky("\n" + "=" * 75, "header")
            self.log_risky(
                f"IDENTIFIED {len(self.discovered_risky_users)} RISKY ACCOUNT(S) [Level: {selected_level.upper()}]:",
                "danger"
            )
            self.log_risky("=" * 75, "header")

            for idx, u in enumerate(filtered_users, start=1):
                upn = u.get("userPrincipalName", "N/A")
                r_lvl = str(u.get("riskLevel", "N/A")).upper()
                detail = u.get("riskDetail", "N/A")
                last_upd = u.get("riskLastUpdatedDateTime", "N/A")
                tag_color = "danger" if r_lvl == "HIGH" else "warn" if r_lvl == "MEDIUM" else "info"
                self.log_risky(
                    f"[{idx}] {upn:<34} | Level: {r_lvl:<6} | Detail: {detail} | Updated: {last_upd}",
                    tag_color
                )

            self.log_risky("=" * 75, "header")
            self.log_risky("[!] Ready to run full sign-ins investigation for these accounts.\n", "info")

            self.lbl_status_risky.configure(
                text=f"Found {len(self.discovered_risky_users)} {selected_level}-risk user(s). Ready to audit."
            )
            self.btn_audit_risky.configure(state="normal")

            preview = "\n".join(self.discovered_risky_users[:5]) + ("\n..." if len(self.discovered_risky_users) > 5 else "")
            if messagebox.askyesno(
                "Risky Users Detected",
                f"Found {len(self.discovered_risky_users)} {selected_level.upper()}-RISK user(s):\n\n{preview}\n\n"
                "Do you want to audit their sign-in logs and generate the bulk report now?"
            ):
                self.start_audit_risky_users()

        except Exception as e:
            self.log_risky(f"\n[!] ERROR querying risky users: {e}", "danger")
            self.lbl_status_risky.configure(text="Error querying risky users.")
            messagebox.showerror("Graph Error", str(e))
        finally:
            self.btn_scan_risky.configure(state="normal")

    def worker_signins_generic(self, target_inputs, days, use_abuse, mode, log_func, prog_bar, status_lbl, trigger_btn, only_sid=False):
        try:
            status_lbl.configure(text="Authenticating via Microsoft Graph...")
            prog_bar.set(0.05)
            token = get_access_token(log_func, scopes=GRAPH_SCOPES, client_id=CLIENT_ID)

            status_lbl.configure(text="Resolving target identifiers...")
            target_users = resolve_targets_to_upns(target_inputs, token, log_func)
            if not target_users:
                log_func("\n[-] No valid accounts resolved.", "danger")
                status_lbl.configure(text="Completed: 0 valid accounts resolved.")
                prog_bar.set(1.0)
                messagebox.showwarning("Resolution Result", "None of the provided SIDs could be matched to an Entra ID user.")
                return

            if only_sid:
                log_func("\n" + "=" * 65, "header")
                log_func(f"SID TRANSLATION SUMMARY ({len(target_users)} ACCOUNT(S)):", "info")
                log_func("=" * 65, "header")
                for upn in target_users:
                    log_func(f" -> {upn}", "success")
                log_func("=" * 65, "header")
                status_lbl.configure(text=f"Done: {len(target_users)} account(s) translated.")
                prog_bar.set(1.0)
                return

            total_accounts = len(target_users)
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            filter_date = cutoff_date.strftime("%Y-%m-%dT%H:%M:%SZ")

            select_fields = (
                "createdDateTime,userPrincipalName,userDisplayName,appDisplayName,"
                "ipAddress,status,location,deviceDetail,appliedConditionalAccessPolicies"
            )

            all_records_global = []
            user_summaries = []
            graph_users_count = 0
            sentinel_users_count = 0
            sentinel_ws_guid = self.get_active_sentinel_workspace_guid()

            log_func(f"[*] Starting audit for {total_accounts} account(s) over the last {days} days...", "info")

            for user_idx, user in enumerate(target_users, start=1):
                status_lbl.configure(text=f"Auditing account {user_idx}/{total_accounts}: {user}...")
                user_events = []
                used_sentinel_this_user = False

                log_func(f"\n[+] [{user_idx}/{total_accounts}] Querying Graph for: {user}...", "info")
                odata_filter = f"userPrincipalName eq '{user}' and createdDateTime ge {filter_date}"
                url = (
                    f"https://graph.microsoft.com/v1.0/auditLogs/signIns?"
                    f"$filter={odata_filter}&$select={select_fields}&$top=50"
                )
                try:
                    while url:
                        retries = 2 if sentinel_ws_guid else 4
                        resp = graph_get_with_retry(url, headers, log_func, max_retries=retries)
                        data = resp.json()
                        user_events.extend(data.get("value", []))
                        url = data.get("@odata.nextLink")
                        if url:
                            time.sleep(0.4)
                    graph_users_count += 1
                except GraphRateLimitError:
                    if sentinel_ws_guid:
                        log_func(
                            "[!] Graph returned 429 Too Many Requests. Falling back to Sentinel SigninLogs for this user...",
                            "warn"
                        )
                        used_sentinel_this_user = True
                        sentinel_users_count += 1
                        status_lbl.configure(text=f"Fallback to Sentinel SigninLogs ({user})...")
                        user_events = fetch_signins_from_sentinel(user, days, sentinel_ws_guid, log_func)
                    else:
                        log_func(
                            "[!] Graph returned 429 and no Sentinel Workspace ID is configured for fallback.",
                            "danger"
                        )
                        raise

                source_label = "Sentinel SigninLogs" if used_sentinel_this_user else "Microsoft Graph"
                log_func(f"    Downloaded {len(user_events)} sign-in event(s) via {source_label}. Parsing...", "muted")

                user_parsed = []
                user_ips = set()
                u_success = 0
                u_failures = 0
                u_malicious = 0
                u_suspicious = 0

                for ev in user_events:
                    status_info = ev.get("status", {}) or {}
                    err_code = status_info.get("errorCode", 0)
                    is_success = (err_code == 0)
                    if is_success:
                        u_success += 1
                    else:
                        u_failures += 1

                    failure_reason_raw = status_info.get("failureReason") or ""
                    failure_desc = ENTRA_ERRORS.get(err_code, failure_reason_raw or "Unknown error.") if not is_success else ""

                    loc = ev.get("location", {}) or {}
                    city = loc.get("city") or ""
                    country = loc.get("countryOrRegion") or ""
                    location = f"{city}, {country}" if city and country else (country or city or "N/A")

                    dev = ev.get("deviceDetail", {}) or {}
                    ca_raw = ev.get("appliedConditionalAccessPolicies") or []
                    ca_list = [f"{p.get('displayName')} ({p.get('result')})" for p in ca_raw if isinstance(p, dict)]
                    ip = ev.get("ipAddress", "N/A")
                    if ip and ip != "N/A":
                        user_ips.add(ip)

                    rec = {
                        "datetime": ev.get("createdDateTime", "N/A"), "user": ev.get("userPrincipalName", user),
                        "user_display": ev.get("userDisplayName", "N/A"), "app": ev.get("appDisplayName", "N/A"),
                        "status": "Success" if is_success else "Failure", "is_success": is_success,
                        "error_code": err_code, "failure_desc": failure_desc, "ip": ip, "location": location,
                        "os": dev.get("operatingSystem") or "N/A", "browser": dev.get("browser") or "N/A",
                        "ca": "; ".join(ca_list) if ca_list else "None / Not Applied"
                    }

                    if use_abuse:
                        abuse_data = check_abuseipdb(ip, log_func)
                        rec["abuse_score"] = abuse_data["score"]
                        rec["abuse_reports"] = abuse_data["reports"]
                        rec["abuse_categories"] = abuse_data["categories"]
                        rec["abuse_risk"] = abuse_data["risk"]

                        if abuse_data["risk"] == "Malicious":
                            u_malicious += 1
                        elif abuse_data["risk"] == "Suspicious":
                            u_suspicious += 1

                    user_parsed.append(rec)

                all_records_global.extend(user_parsed)

                user_summaries.append({
                    "user": user,
                    "total": len(user_parsed),
                    "success": u_success,
                    "failures": u_failures,
                    "malicious": u_malicious,
                    "suspicious": u_suspicious,
                    "unique_ips": len(user_ips)
                })

                prog_val = 0.1 + (0.75 * (user_idx / total_accounts))
                prog_bar.set(prog_val)

                if user_idx < total_accounts:
                    time.sleep(0.5)

            if not all_records_global:
                log_func("\n[-] No sign-in logs found for the selected account(s).", "warn")
                status_lbl.configure(text="Completed: 0 logs.")
                prog_bar.set(1.0)
                messagebox.showinfo("Result", "No sign-in logs were found for the requested timeframe.")
                return

            status_lbl.configure(text="Generating single unified CSV and HTML...")
            ts = f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}"
            mode_tag = "intel" if use_abuse else "std"

            if mode == "single":
                title_label = target_users[0]
                slug = target_users[0].replace("@", "_").replace(".", "_")
                csv_file = os.path.join(get_output_dir("signins"), f"signins_{mode_tag}_{slug}_{days}d_{ts}.csv")
                html_file = os.path.join(get_output_dir("signins"), f"signins_{mode_tag}_{slug}_{days}d_{ts}.html")
            elif mode.startswith("risky_"):
                lvl_tag = mode.replace("risky_", "").upper()
                title_label = f"{lvl_tag}-RISK Users Audit ({total_accounts} Accounts)"
                csv_file = os.path.join(get_output_dir("signins"), f"signins_{mode_tag}_RISKY_{lvl_tag}_{total_accounts}accounts_{days}d_{ts}.csv")
                html_file = os.path.join(get_output_dir("signins"), f"signins_{mode_tag}_RISKY_{lvl_tag}_{total_accounts}accounts_{days}d_{ts}.html")
            else:
                title_label = f"Bulk Audit ({total_accounts} Accounts)"
                csv_file = os.path.join(get_output_dir("signins"), f"signins_{mode_tag}_bulk_{total_accounts}accounts_{days}d_{ts}.csv")
                html_file = os.path.join(get_output_dir("signins"), f"signins_{mode_tag}_bulk_{total_accounts}accounts_{days}d_{ts}.html")

            with open(csv_file, mode="w", newline="", encoding="utf-8-sig") as f:
                fields = ["Date and Time", "User", "User Display", "APP", "Status", "ErrorCode", "Failure Meaning", "IP", "Location", "OS", "Device Browser", "Conditional Access"]
                if use_abuse:
                    fields.extend(["Abuse Score", "Abuse Reports", "Abuse Risk", "Attack Categories"])
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for r in all_records_global:
                    row = {
                        "Date and Time": r["datetime"], "User": r["user"], "User Display": r.get("user_display", ""),
                        "APP": r["app"], "Status": r["status"], "ErrorCode": r["error_code"], "Failure Meaning": r["failure_desc"],
                        "IP": r["ip"], "Location": r["location"], "OS": r["os"],
                        "Device Browser": r["browser"], "Conditional Access": r["ca"]
                    }
                    if use_abuse:
                        row.update({
                            "Abuse Score": f"{r.get('abuse_score', 0)}%", "Abuse Reports": r.get('abuse_reports', 0),
                            "Abuse Risk": r.get('abuse_risk', 'N/A'), "Attack Categories": "; ".join(r.get('abuse_categories', []))
                        })
                    writer.writerow(row)

            export_signins_html(html_file, title_label, days, all_records_global, user_summaries, use_abuseip=use_abuse)

            if sentinel_users_count == 0:
                source_summary = "Microsoft Graph API"
                source_tag = "info"
            elif graph_users_count == 0:
                source_summary = "Sentinel SigninLogs (429 Fallback)"
                source_tag = "warn"
            else:
                source_summary = f"Mixed (Graph: {graph_users_count} | Sentinel Fallback: {sentinel_users_count})"
                source_tag = "warn"

            log_func("\n" + "=" * 65, "header")
            log_func(f"AUDIT SUMMARY — {title_label} ({days} DAYS):", "info")
            log_func(f" Data Source      : {source_summary}", source_tag)
            log_func(f" Accounts Queried : {total_accounts}")
            log_func(f" Total Logins     : {len(all_records_global)}")
            log_func(f" Successful       : {sum(1 for r in all_records_global if r['is_success'])}", "success")
            log_func(f" Failed           : {sum(1 for r in all_records_global if not r['is_success'])}", "danger")
            if use_abuse:
                log_func(f" Unique IPs Pool  : {len(IP_CACHE)} IPs checked", "warn")
            log_func(f"[+] Unified CSV   : {csv_file}", "success")
            log_func(f"[+] Unified HTML  : {html_file}", "success")
            log_func("=" * 65, "header")

            status_lbl.configure(text="Audit completed successfully.")
            prog_bar.set(1.0)

            if messagebox.askyesno("Complete", f"Audit finished successfully for {total_accounts} account(s).\n\nOpen HTML report in browser?"):
                os.startfile(os.path.abspath(html_file))

        except Exception as e:
            log_func(f"\n[!] ERROR: {e}", "danger")
            status_lbl.configure(text="Error occurred.")
            messagebox.showerror("Execution Error", str(e))
        finally:
            trigger_btn.configure(state="normal")
            if hasattr(self, 'btn_audit_risky'):
                self.btn_audit_risky.configure(state="normal" if self.discovered_risky_users else "disabled")

    # ---------------------------------------------------------------------
    # TAB 3: Sentinel / Defender XDR KQL Hunting
    # ---------------------------------------------------------------------

    def worker_sentinel_query(self, engine, ws_guid, raw_ws_label, kql, use_abuse):
        try:
            self.prog_sentinel.set(0.1)
            columns = []
            records = []

            if engine == "Defender XDR (Graph)":
                self.lbl_status_sentinel.configure(text="Authenticating via Microsoft Graph...")
                token = get_access_token(self.log_sentinel, scopes=GRAPH_SCOPES, client_id=CLIENT_ID)
                self.prog_sentinel.set(0.35)

                url = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
                headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                self.log_sentinel("[*] Executing KQL via Graph runHuntingQuery...", "info")
                self.lbl_status_sentinel.configure(text="Running Graph Hunting query...")

                resp = requests.post(url, headers=headers, json={"Query": kql}, timeout=90, verify=False)
                if not resp.ok:
                    raise Exception(f"Graph HTTP {resp.status_code}: {resp.text}")

                data = resp.json()
                schema = data.get("schema", [])
                results = data.get("results", [])
                columns = [col.get("name") for col in schema] if schema else (list(results[0].keys()) if results else [])
                records = results

            else:
                self.lbl_status_sentinel.configure(text="Authenticating via Log Analytics API (Azure CLI Client)...")
                token = get_access_token(
                    self.log_sentinel,
                    scopes=LOG_ANALYTICS_SCOPES,
                    client_id=AZURE_CLI_CLIENT_ID
                )
                self.prog_sentinel.set(0.35)

                url = f"https://api.loganalytics.io/v1/workspaces/{ws_guid}/query"
                headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                self.log_sentinel(f"[*] Executing KQL against Sentinel Workspace {ws_guid}...", "info")
                self.lbl_status_sentinel.configure(text="Running Sentinel KQL query...")

                resp = requests.post(url, headers=headers, json={"query": kql}, timeout=90, verify=False)
                if not resp.ok:
                    raise Exception(f"Log Analytics HTTP {resp.status_code}: {resp.text}")

                data = resp.json()
                tables = data.get("tables", [])
                if tables:
                    columns = [c["name"] for c in tables[0].get("columns", [])]
                    raw_rows = tables[0].get("rows", [])
                    records = [dict(zip(columns, row)) for row in raw_rows]

            self.prog_sentinel.set(0.6)
            total_rows = len(records)
            self.log_sentinel(f"[+] Query returned {total_rows} row(s) across {len(columns)} column(s).", "success")

            if total_rows == 0:
                self.lbl_status_sentinel.configure(text="Completed: 0 rows returned.")
                self.prog_sentinel.set(1.0)
                messagebox.showinfo("KQL Result", "The query completed successfully but returned 0 records.")
                return

            if use_abuse:
                self.lbl_status_sentinel.configure(text="Enriching detected public IPs with AbuseIPDB...")
                self.log_sentinel("[*] Scanning rows for public IPv4 addresses...", "info")

                for idx, row in enumerate(records, start=1):
                    row_text = " ".join(str(v) for v in row.values() if v is not None)
                    found_ips = []
                    seen_row_ips = set()
                    for match in IPV4_REGEX.findall(row_text):
                        if match not in seen_row_ips and is_public_ip(match):
                            seen_row_ips.add(match)
                            found_ips.append(match)

                    row["_detected_ips"] = found_ips
                    if found_ips:
                        best_score = -1
                        best_risk = "Clean"
                        all_cats = set()
                        for ip in found_ips:
                            ab = check_abuseipdb(ip, self.log_sentinel)
                            if ab["score"] > best_score:
                                best_score = ab["score"]
                                best_risk = ab["risk"]
                            for c in ab.get("categories", []):
                                all_cats.add(c)
                        row["_abuse_score"] = max(best_score, 0)
                        row["_abuse_risk"] = best_risk
                        row["_abuse_cats"] = ", ".join(sorted(all_cats)) if all_cats else "Clean"
                    else:
                        row["_abuse_score"] = 0
                        row["_abuse_risk"] = "N/A"
                        row["_abuse_cats"] = "No public IP"

                    if idx % 10 == 0 or idx == total_rows:
                        self.prog_sentinel.set(0.6 + (0.3 * (idx / total_rows)))

            ts = f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}"
            eng_slug = "xdr_graph" if engine == "Defender XDR (Graph)" else "sentinel_ws"
            csv_file = os.path.join(get_output_dir("sentinel"), f"{eng_slug}_query_{ts}.csv")
            html_file = os.path.join(get_output_dir("sentinel"), f"{eng_slug}_query_{ts}.html")

            csv_cols = list(columns)
            if use_abuse:
                csv_cols.extend(["Detected IPs", "Max Abuse Score", "Threat Risk", "Categories"])

            with open(csv_file, mode="w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=csv_cols)
                writer.writeheader()
                for r in records:
                    out_row = {c: r.get(c, "") for c in columns}
                    if use_abuse:
                        out_row["Detected IPs"] = "; ".join(r.get("_detected_ips", []))
                        out_row["Max Abuse Score"] = f"{r.get('_abuse_score', 0)}%"
                        out_row["Threat Risk"] = r.get("_abuse_risk", "N/A")
                        out_row["Categories"] = r.get("_abuse_cats", "")
                    writer.writerow(out_row)

            ws_display = raw_ws_label if engine == "Sentinel Workspace" else ""
            export_sentinel_html(html_file, engine, ws_display, kql, columns, records, use_abuseip=use_abuse)

            self.log_sentinel("\n" + "=" * 70, "header")
            self.log_sentinel(f"HUNTING SUMMARY — {engine} ({total_rows} ROWS):", "info")
            for preview_idx, r in enumerate(records[:5], start=1):
                preview_items = [f"{k}={r.get(k)}" for k in columns[:4]]
                risk_tag = "danger" if r.get("_abuse_risk") == "Malicious" else "warn" if r.get("_abuse_risk") == "Suspicious" else "default"
                self.log_sentinel(f" [{preview_idx}] " + " | ".join(preview_items), risk_tag)
            if total_rows > 5:
                self.log_sentinel(f" ... ({total_rows - 5} more rows exported to HTML/CSV)", "muted")
            self.log_sentinel(f"[+] Exported CSV  : {csv_file}", "success")
            self.log_sentinel(f"[+] Exported HTML : {html_file}", "success")
            self.log_sentinel("=" * 70, "header")

            self.lbl_status_sentinel.configure(text=f"Completed: {total_rows} row(s) exported.")
            self.prog_sentinel.set(1.0)

            if messagebox.askyesno("Complete", f"KQL query finished ({total_rows} rows).\n\nOpen HTML report in browser?"):
                os.startfile(os.path.abspath(html_file))

        except Exception as e:
            self.log_sentinel(f"\n[!] ERROR: {e}", "danger")
            self.lbl_status_sentinel.configure(text="Error executing KQL query.")
            messagebox.showerror("Hunting Query Error", str(e))
        finally:
            self.btn_run_kql.configure(state="normal")
            if self.seg_sentinel_engine.get() == "Sentinel Workspace":
                self.btn_discover_ws.configure(state="normal")

    # ---------------------------------------------------------------------
    # TAB 4: IP Threat Searcher (Single, Bulk .txt, & Weekly PaloAlto IPS)
    # ---------------------------------------------------------------------

    def worker_ip_search(self, mode, target, use_intigriti, sentinel_days=30):
        try:
            if mode == "single":
                self.log_ip(f"[*] Evaluating IP: {target} (Check Intigriti first: {use_intigriti})...", "info")
                self.lbl_status_ip.configure(text="Querying IP...")
                self.prog_ip.set(0.3)

                if use_intigriti and check_intigriti_ip(target, self.log_ip):
                    self.prog_ip.set(1.0)
                    self.log_ip("\n" + "=" * 55, "header")
                    self.log_ip(f" RESULT: {target} — INTIGRITI VERIFIED", "info")
                    self.log_ip("=" * 55, "header")
                    self.log_ip(" Intigriti   : YES (exists=True)", "info")
                    self.log_ip(" Action      : Skipping AbuseIPDB & excluding from exports.", "warn")
                    self.log_ip("=" * 55 + "\n", "header")
                    self.lbl_status_ip.configure(text="Intigriti IP verified (skipped AbuseIPDB).")
                    return

                res = check_abuseipdb(target, self.log_ip)
                self.prog_ip.set(1.0)

                self.log_ip("\n" + "=" * 55, "header")
                self.log_ip(f" RESULT: {target}", "info")
                self.log_ip("=" * 55, "header")
                if use_intigriti:
                    self.log_ip(" Intigriti   : No (exists=False)")
                self.log_ip(f" Country     : {res.get('country', 'N/A')}")
                self.log_ip(f" ISP         : {res.get('isp', 'N/A')}")
                self.log_ip(f" Domain      : {res.get('domain', 'N/A')}")
                self.log_ip(f" Reports     : {res.get('reports', 0)} (90 days)")

                risk = res.get('risk', 'Clean')
                color_tag = "danger" if risk == "Malicious" else "warn" if risk == "Suspicious" else "success"
                self.log_ip(f" Risk / Score: {res.get('score', 0)}% ({risk})", color_tag)
                self.log_ip(f" Categories  : {', '.join(res.get('categories', [])) if res.get('categories') else 'None'}")
                self.log_ip("=" * 55 + "\n", "header")
                self.lbl_status_ip.configure(text="Lookup completed.")
                return

            # Bulk modes: .txt file or Weekly PaloAlto IPS (Sentinel KQL)
            ips = []
            source_slug = ""

            if mode == "bulk":
                self.log_ip(f"[*] Parsing target IPs from: {target}...", "info")
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                raw_ips = IPV4_REGEX.findall(content)
                seen = set()
                ips = [x for x in raw_ips if not (x in seen or seen.add(x))]
                source_slug = os.path.splitext(os.path.basename(target))[0]

                if not ips:
                    self.log_ip("[-] No valid IPv4 addresses detected.", "danger")
                    self.lbl_status_ip.configure(text="No IPs found.")
                    return

            elif mode == "sentinel":
                self.lbl_status_ip.configure(text="Authenticating via Log Analytics API...")
                self.prog_ip.set(0.08)
                la_token = get_access_token(
                    self.log_ip,
                    scopes=LOG_ANALYTICS_SCOPES,
                    client_id=AZURE_CLI_CLIENT_ID
                )

                kql = (
                    "union\n"
                    "    (UC_372 | project IP = SourceIP, Organization = Affiliate),\n"
                    "    (UC_035 | project IP = SourceIP, Organization = Affiliate)\n"
                    "| where IP !in (\"54.76.136.167\",\"54.229.147.145\",\"34.240.52.44\",\"52.212.181.129\",\"34.249.21.72\","
                    "\"150.45.87.90\",\"150.45.100.250\",\"150.45.100.225\",\"150.45.100.226\",\"150.45.89.240\",\"150.45.80.240\","
                    "\"150.45.83.201\",\"150.45.88.98\",\"150.45.86.121\",\"150.45.86.202\",\"150.45.86.82\",\" \",\"\",\"150.45.88.45\")\n"
                    "| where IP !startswith \"10.\"\n"
                    "| summarize IP = strcat_array(make_set(IP), \", \"), IPCount = dcount(IP) by Organization\n"
                    "| where Organization == \"TME\"\n"
                    "| project IP"
                )

                self.log_ip(f"[*] Querying Weekly PaloAlto IPS (WS: {target} | Timespan: P{sentinel_days}D)...", "info")
                self.lbl_status_ip.configure(text=f"Executing KQL (last {sentinel_days}d)...")
                self.prog_ip.set(0.18)

                url = f"https://api.loganalytics.io/v1/workspaces/{target}/query"
                headers = {"Authorization": f"Bearer {la_token}", "Content-Type": "application/json"}
                payload = {
                    "query": kql,
                    "timespan": f"P{sentinel_days}D"
                }
                resp = requests.post(url, headers=headers, json=payload, timeout=90, verify=False)
                if not resp.ok:
                    raise Exception(f"Log Analytics HTTP {resp.status_code}: {resp.text}")

                data = resp.json()
                tables = data.get("tables", [])
                raw_text_chunks = []
                if tables:
                    for row in tables[0].get("rows", []):
                        for cell in row:
                            if cell is not None:
                                raw_text_chunks.append(str(cell))

                raw_ips = IPV4_REGEX.findall(" ".join(raw_text_chunks))
                seen = set()
                ips = [x for x in raw_ips if not (x in seen or seen.add(x))]
                source_slug = f"weekly_paloalto_{sentinel_days}d"

                if not ips:
                    self.log_ip(f"[-] Sentinel KQL returned 0 IPs for Organization 'TME' in the last {sentinel_days} day(s).", "warn")
                    self.lbl_status_ip.configure(text="Completed: 0 IPs found in Sentinel.")
                    self.prog_ip.set(1.0)
                    messagebox.showinfo("Sentinel Result", f"No IPs returned by the query in the last {sentinel_days} day(s).")
                    return

            total_ips = len(ips)
            self.log_ip(f"[+] Found {total_ips} unique IP(s). Starting Intigriti + AbuseIPDB check (Filter active: {use_intigriti})...\n", "success")

            results = []
            skipped_intigriti = 0
            skipped_low_score = 0

            for idx, ip in enumerate(ips, start=1):
                if use_intigriti and check_intigriti_ip(ip, self.log_ip):
                    skipped_intigriti += 1
                    self.log_ip(f"[{idx}/{total_ips}] {ip:<15} -> Intigriti IP (exists=True) | Skipped", "info")
                    self.prog_ip.set(0.2 + (0.75 * (idx / total_ips)))
                    self.lbl_status_ip.configure(text=f"Processed ({idx}/{total_ips})...")
                    continue

                res = check_abuseipdb(ip, self.log_ip)
                score = res.get("score", 0)

                if use_intigriti and score <= 10:
                    skipped_low_score += 1
                    self.log_ip(f"[{idx}/{total_ips}] {ip:<15} -> {score}% (<= 10%) | Omitted from export", "muted")
                    self.prog_ip.set(0.2 + (0.75 * (idx / total_ips)))
                    self.lbl_status_ip.configure(text=f"Processed ({idx}/{total_ips})...")
                    continue

                results.append({"ip": ip, **res})

                risk = res.get('risk', 'Clean')
                color_tag = "danger" if risk == "Malicious" else "warn" if risk == "Suspicious" else "success"
                self.log_ip(f"[{idx}/{total_ips}] {ip:<15} -> {score}% ({risk}) | Added to export", color_tag)

                self.prog_ip.set(0.2 + (0.75 * (idx / total_ips)))
                self.lbl_status_ip.configure(text=f"Processed ({idx}/{total_ips})...")

            if not results:
                self.log_ip("\n" + "=" * 60, "header")
                self.log_ip(f" BULK FINISHED | Intigriti skipped: {skipped_intigriti} | Low score skipped: {skipped_low_score}", "info")
                self.log_ip(" No actionable IPs left to export.", "warn")
                self.log_ip("=" * 60, "header")
                self.lbl_status_ip.configure(text="Completed (0 IPs met export criteria).")
                self.prog_ip.set(1.0)
                messagebox.showinfo("Complete", f"Finished checking {total_ips} IP(s).\nNo IPs met the export criteria.")
                return

            ts = f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}"
            html_file = os.path.join(get_output_dir("abuseip"), f"abuseipdb_{source_slug}_{ts}.html")
            txt_block_file = os.path.join(get_output_dir("abuseip"), f"blocklist_{source_slug}_{ts}.txt")
            csv_ext_file = os.path.join(get_output_dir("abuseip"), f"extended_{source_slug}_{ts}.csv")

            export_ipsearcher_html(
                html_file,
                results,
                skipped_intigriti_count=skipped_intigriti,
                skipped_low_score_count=skipped_low_score
            )
            export_ipsearcher_blocklist_and_csv(txt_block_file, csv_ext_file, results)

            block_cidrs = [f"{r['ip']}/32" for r in results if r.get("score", 0) > 10]

            self.log_ip("\n" + "=" * 60, "header")
            self.log_ip(f" FINISHED | INPUT IPs: {total_ips}", "info")
            if use_intigriti:
                self.log_ip(f" Excluded (Intigriti)   : {skipped_intigriti} IP(s)", "warn")
                self.log_ip(f" Omitted (Score <= 10%) : {skipped_low_score} IP(s)", "muted")
            self.log_ip(f" Exported Actionable    : {len(results)} IP(s)", "success")
            self.log_ip(f"[+] HTML Dashboard      : {html_file}", "success")
            self.log_ip(f"[+] Extended CSV        : {csv_ext_file}", "success")
            self.log_ip(f"[+] Blocklist TXT       : {txt_block_file}", "success")
            if block_cidrs:
                self.log_ip("-" * 60, "header")
                self.log_ip("BLOCKLIST (/32) READY TO COPY:", "warn")
                for cidr in block_cidrs:
                    self.log_ip(cidr, "default")
            self.log_ip("=" * 60, "header")

            self.lbl_status_ip.configure(text="Analysis completed.")
            self.prog_ip.set(1.0)
            if messagebox.askyesno("Complete", f"Lookup finished.\nExported {len(results)} IP(s) and generated blocklist TXT.\n\nOpen HTML report in browser?"):
                os.startfile(os.path.abspath(html_file))
        except Exception as e:
            self.log_ip(f"\n[!] ERROR: {e}", "danger")
            self.lbl_status_ip.configure(text="Error occurred.")
            messagebox.showerror("Error", str(e))
        finally:
            self.btn_run_ipsearch.configure(state="normal")

    # ---------------------------------------------------------------------
    # TAB 5: API Keys Status Monitor
    # ---------------------------------------------------------------------
