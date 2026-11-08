"""Firmware Upgrade Manager (spec Module H).

Profiles
    One per manufacturer / model pattern (/ chassis / mainboard pattern) / method,
    each citing the manufacturer's documentation. A profile can only be used to
    *execute* after an operator explicitly marks it verified (who/when recorded).

Session steps (each recorded in ``steps_json`` and the audit log)
    1 identification   model, board/chassis, SoC, panel, current firmware version
    2 compatibility    Compatibility Analyzer verdict (execution needs VERIFIED COMPATIBLE)
    3 validation       SHA-256, integrity, format vs documented package, source, signature info
    4 backup           what was really saved (never claims a full backup that does not exist)
    5 preparation      risks, method, power/connection/USB checks, typed confirmation
    6 execution        only Official USB preparation; everything else = instructions
    7 verification     version/model/panel/basic functions/boot after the TV updated itself
    8 recovery         documented recovery; rollback only if documented
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict

from app.modules.upgrade_manager.adapters import METHODS, ExecutionResult
from app.security.audit import current_actor
from app.security.hashing import sha256_file

STEPS = ["identification", "compatibility", "validation", "backup", "preparation", "execution", "verification",
         "recovery"]
PROFILE_FIELDS = ["manufacturer", "model_pattern", "chassis", "mainboard_pattern", "method", "instructions",
                  "documentation_url", "documentation_ref", "package_pattern", "usb_filesystems", "usb_target_path",
                  "usb_target_name", "power_requirements", "verification_steps", "recovery_procedure",
                  "rollback_documented", "risk_level", "notes"]
BASIC_FUNCTIONS = ["boots to home screen", "picture on all inputs", "sound", "remote control", "network", "tuner/channels"]


class UpgradeBlocked(Exception):
    pass


class UpgradeManager:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db, self.audit = ctx.db, ctx.audit

    # ---- profiles --------------------------------------------------------------------------------
    def add_profile(self, rec: dict) -> int:
        r = {k: (rec.get(k).strip() if isinstance(rec.get(k), str) else rec.get(k)) for k in PROFILE_FIELDS}
        if not r["manufacturer"] or not r["model_pattern"]:
            raise ValueError("manufacturer and model pattern are required (use '*' deliberately for all models)")
        if r["method"] not in METHODS:
            raise ValueError(f"method must be one of {list(METHODS)}")
        if not r["documentation_ref"] or len(r["documentation_ref"]) < 8:
            raise ValueError("documentation_ref is required: cite the manufacturer's upgrade instructions "
                             "(manual title/section or official support page)")
        r["risk_level"] = (r["risk_level"] or METHODS[r["method"]].default_risk).lower()
        if r["risk_level"] not in ("low", "medium", "high", "critical"):
            raise ValueError("risk_level must be low/medium/high/critical")
        r["rollback_documented"] = 1 if r["rollback_documented"] else 0
        cols = PROFILE_FIELDS + ["verified", "created_at"]
        pid = self.db.execute(f"INSERT INTO firmware_upgrade_profiles({','.join(cols)}) VALUES "
                              f"({','.join('?' * len(PROFILE_FIELDS))}, 0, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                              tuple(r[k] for k in PROFILE_FIELDS))
        self.audit.record("upgrade.profile_add", "upgrade_profile", pid, method=r["method"], manufacturer=r["manufacturer"])
        return pid

    def verify_profile(self, profile_id: int, typed: str, verified_by: str | None = None) -> None:
        """Operator states the profile was checked against the cited documentation."""
        p = self.profile(profile_id)
        if typed.strip() != f"VERIFIED {p['manufacturer']}":
            raise ValueError(f"Type exactly: VERIFIED {p['manufacturer']}")
        self.db.execute("UPDATE firmware_upgrade_profiles SET verified=1, verified_by=?,"
                        " verified_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                        (verified_by or current_actor(), profile_id))
        self.audit.record("upgrade.profile_verify", "upgrade_profile", profile_id)

    def profile(self, pid: int) -> dict:
        r = self.db.query_one("SELECT * FROM firmware_upgrade_profiles WHERE id=?", (pid,))
        if r is None:
            raise KeyError(pid)
        return dict(r)

    def profiles(self) -> list[dict]:
        return [dict(r) for r in self.db.query("SELECT * FROM firmware_upgrade_profiles ORDER BY manufacturer, id")]

    def applicable_profiles(self, project) -> list[dict]:
        out = []
        for p in self.profiles():
            if not project.manufacturer or p["manufacturer"].lower() != project.manufacturer.lower():
                continue
            if not project.model_number or not fnmatch.fnmatch(project.model_number.upper(), p["model_pattern"].upper()):
                continue
            if p["chassis"] and (not project.chassis or p["chassis"].upper() != project.chassis.upper()):
                continue
            if p["mainboard_pattern"] and (not project.mainboard or
                                           not fnmatch.fnmatch(project.mainboard.upper(), p["mainboard_pattern"].upper())):
                continue
            out.append(p)
        return out

    # ---- sessions ------------------------------------------------------------------------------------
    def start(self, project_id: int, profile_id: int, target_firmware_id: int) -> int:
        proj = self.ctx.projects.get(project_id)
        prof = self.profile(profile_id)
        if prof not in self.applicable_profiles(proj):
            raise UpgradeBlocked("This profile does not apply to the TV (manufacturer / model / chassis / board).")
        self.ctx.library.get(target_firmware_id)
        sid = self.db.execute("INSERT INTO firmware_upgrade_sessions(project_id, profile_id, source_firmware_version,"
                              " target_firmware_id, status, method, steps_json, created_at) VALUES (?,?,?,?,?,?,?,"
                              " strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                              (project_id, profile_id, proj.firmware_version, target_firmware_id, "started",
                               prof["method"], json.dumps({s: {"status": "pending"} for s in STEPS})))
        self._log(sid, f"Session started: method {prof['method']}, profile #{profile_id}, target firmware "
                       f"#{target_firmware_id}")
        self.audit.record("upgrade.start", "tv_project", project_id, session_id=sid, profile_id=profile_id,
                          firmware_id=target_firmware_id)
        return sid

    def session(self, sid: int) -> dict:
        r = self.db.query_one("SELECT * FROM firmware_upgrade_sessions WHERE id=?", (sid,))
        if r is None:
            raise KeyError(sid)
        d = dict(r)
        d["steps"] = json.loads(d["steps_json"] or "{}")
        return d

    def sessions(self, project_id: int) -> list[dict]:
        return [self.session(r[0]) for r in self.db.query(
            "SELECT id FROM firmware_upgrade_sessions WHERE project_id=? ORDER BY id DESC", (project_id,))]

    def _log(self, sid: int, line: str) -> None:
        cur = self.db.scalar("SELECT log FROM firmware_upgrade_sessions WHERE id=?", (sid,)) or ""
        ts = self.db.scalar("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')")
        self.db.execute("UPDATE firmware_upgrade_sessions SET log=? WHERE id=?", (cur + f"[{ts}] {line}\n", sid))

    def _set_step(self, sid: int, step: str, status: str, **data) -> dict:
        s = self.session(sid)
        s["steps"][step] = {"status": status, **data}
        self.db.execute("UPDATE firmware_upgrade_sessions SET steps_json=?, status=? WHERE id=?",
                        (json.dumps(s["steps"], default=str), f"{step}:{status}", sid))
        self._log(sid, f"Step {step}: {status}")
        self.audit.record(f"upgrade.step.{step}", "tv_project", s["project_id"], session_id=sid, status=status)
        return s["steps"][step]

    def _require(self, sid: int, *steps: str) -> dict:
        s = self.session(sid)
        for st in steps:
            if s["steps"].get(st, {}).get("status") not in ("passed", "done", "warning"):
                raise UpgradeBlocked(f"Step '{st}' must be completed first")
        return s

    # step 1
    def step_identification(self, sid: int) -> dict:
        s = self.session(sid)
        p = self.ctx.projects.get(s["project_id"])
        comps = self.ctx.hardware.list(p.id)
        soc = next((c["part_number"] for c in comps if c["component_type"] == "soc"), None)
        found = {"model": p.model_number, "mainboard": p.mainboard, "chassis": p.chassis, "pcb_revision": p.pcb_revision,
                 "soc": soc, "panel": p.panel_model, "current_firmware": p.firmware_version,
                 "identification_status": p.identification_status,
                 "target_firmware": self.ctx.library.get(s["target_firmware_id"]).original_filename}
        missing_req = [k for k in ("model", "current_firmware") if not found[k]]
        if not (p.mainboard or p.chassis):
            missing_req.append("mainboard or chassis")
        missing_opt = [k for k in ("soc", "panel", "pcb_revision") if not found[k]]
        status = "failed" if missing_req else ("warning" if missing_opt else "passed")
        return self._set_step(sid, "identification", status, values=found, missing_required=missing_req,
                              missing_optional=missing_opt)

    # step 2
    def step_compatibility(self, sid: int, baseline_id: int | None = None) -> dict:
        s = self._require(sid, "identification")
        r = self.ctx.compatibility.evaluate(s["project_id"], s["target_firmware_id"], baseline_id)
        self.db.execute("UPDATE firmware_upgrade_sessions SET compatibility_id=? WHERE id=?", (r.id, sid))
        status = "passed" if r.verdict == "VERIFIED COMPATIBLE" else ("failed" if r.verdict == "INCOMPATIBLE" else "warning")
        return self._set_step(sid, "compatibility", status, verdict=r.verdict, score=r.score, reasons=r.reasons,
                              compatibility_id=r.id)

    # step 3
    def step_validation(self, sid: int) -> dict:
        s = self._require(sid, "identification", "compatibility")
        fw = self.ctx.library.get(s["target_firmware_id"])
        prof = self.profile(s["profile_id"])
        checks = []
        ok_hash = sha256_file(fw.stored_path) == fw.sha256
        checks.append({"name": "SHA-256", "ok": ok_hash, "detail": fw.sha256})
        integ = self.ctx.library.verify_integrity(fw.id).verification_status
        checks.append({"name": "File integrity", "ok": integ in ("hash_ok", "verified"), "detail": integ})
        if prof["package_pattern"]:
            m = fnmatch.fnmatch(fw.original_filename.lower(), prof["package_pattern"].lower())
            checks.append({"name": "Package name vs documentation", "ok": m,
                           "detail": f"{fw.original_filename} vs {prof['package_pattern']}"})
        run = self.ctx.firmware.latest_run(fw.id)
        meta = self.ctx.firmware.metadata(run["id"]) if run else []
        checks.append({"name": "Firmware metadata", "ok": bool(run),
                       "detail": f"analysis run #{run['id']}, {len(meta)} facts" if run else "not analysed"})
        checks.append({"name": "File format", "ok": bool(fw.detected_format) and "unknown" not in (fw.detected_format or ""),
                       "detail": fw.detected_format or "unknown"})
        sig = [m["value"] for m in meta if m["attribute"] == "signing"]
        checks.append({"name": "Digital signature", "ok": None,
                       "detail": (sig[0] + " (presence only; keys not verified)") if sig else
                       "no signature metadata — the TV's updater verifies vendor packages itself"})
        src = self.db.query_one("SELECT verification_status FROM firmware_search_results WHERE firmware_id=? "
                                "ORDER BY id DESC LIMIT 1", (fw.id,))
        reliable = fw.category == "Official" or bool(src and "matches the value published" in (src[0] or ""))
        checks.append({"name": "Source reliability", "ok": reliable,
                       "detail": f"{fw.category}; {src[0] if src else 'local import'}"})
        comp = s["steps"]["compatibility"]
        checks.append({"name": "Compatibility report", "ok": comp.get("verdict") == "VERIFIED COMPATIBLE",
                       "detail": f"{comp.get('verdict')} (report #{comp.get('compatibility_id')})"})
        failed = [c for c in checks if c["ok"] is False]
        return self._set_step(sid, "validation", "failed" if failed else "passed", checks=checks)

    # step 4
    def step_backup(self, sid: int, config_export: str | None = None, operator_notes: str | None = None) -> dict:
        s = self._require(sid, "identification")
        p = self.ctx.projects.get(s["project_id"])
        originals = [f for f in self.ctx.library.list(project_id=p.id) if f.category == "Original"
                     and f.id != s["target_firmware_id"]]
        hw_report = self.ctx.hardware_reports.generate_pdf(p.id)
        items = {
            "original_firmware_version": p.firmware_version or "UNKNOWN",
            "full_firmware_image": (f"YES — library firmware #{originals[0].id} {originals[0].original_filename} "
                                    f"(SHA-256 {originals[0].sha256[:16]}…)") if originals else
                                   "NO — only metadata is saved. No full image of the current firmware is available.",
            "configuration_export": config_export or "not performed / no official export mechanism recorded",
            "hardware_report": str(hw_report),
            "notes": operator_notes or "",
        }
        self.db.execute("UPDATE firmware_upgrade_sessions SET backup_json=? WHERE id=?", (json.dumps(items), sid))
        status = "done" if originals else "warning"
        return self._set_step(sid, "backup", status, items=items)

    # step 5
    def risks(self, sid: int) -> list[str]:
        s = self.session(sid)
        prof = self.profile(s["profile_id"])
        m = METHODS[prof["method"]]
        out = [f"Method '{m.label}' — risk level {prof['risk_level']}. {m.summary}",
               "Power loss or removing the medium during the TV's update can make it unbootable.",
               "Rollback: " + ("documented — see recovery step" if prof["rollback_documented"] else
                               "NOT documented for this model; do not assume the previous firmware can be restored.")]
        comp = s["steps"].get("compatibility", {})
        out += [f"Compatibility: {comp.get('verdict')}"] + [f"  • {r}" for r in comp.get("reasons", [])]
        if "NO —" in (s["steps"].get("backup", {}).get("items", {}).get("full_firmware_image", "")):
            out.append("No full image of the current firmware is saved.")
        return out

    def confirmation_phrase(self, sid: int) -> str:
        p = self.ctx.projects.get(self.session(sid)["project_id"])
        return f"UPGRADE {p.model_number}"

    def step_preparation(self, sid: int, power_confirmed: bool, connection_confirmed: bool, typed: str,
                         usb_target: str | None = None, fs_probe=None) -> dict:
        s = self._require(sid, "identification", "compatibility", "validation", "backup")
        prof = self.profile(s["profile_id"])
        fw = self.ctx.library.get(s["target_firmware_id"])
        m = METHODS[prof["method"]]
        checks = [{"name": "Stable power (UPS / no storm)", "ok": bool(power_confirmed), "detail": prof["power_requirements"] or ""},
                  {"name": "Connection / medium ready", "ok": bool(connection_confirmed), "detail": ""}]
        if m.executes:
            checks += [asdict(c) for c in m.preflight(prof, fw, usb_target, fs_probe)]
        if typed.strip() != self.confirmation_phrase(sid):
            checks.append({"name": "User confirmation", "ok": False, "detail": f"type exactly: {self.confirmation_phrase(sid)}"})
        else:
            checks.append({"name": "User confirmation", "ok": True, "detail": f"confirmed by {current_actor()}"})
        executable = (m.executes and bool(prof["verified"]) and s["steps"]["compatibility"].get("verdict") ==
                      "VERIFIED COMPATIBLE" and s["steps"]["validation"]["status"] == "passed")
        blocking = [c for c in checks if c["ok"] is False]
        prep = {"checks": checks, "risks": self.risks(sid), "method": m.label, "usb_target": usb_target,
                "instructions": m.instructions(prof, fw), "executable": executable,
                "why_not_executable": [] if executable else [x for x, cond in (
                    ("method is instruction-only (technician report)", not m.executes),
                    ("profile not verified against its documentation", not prof["verified"]),
                    ("compatibility is not VERIFIED COMPATIBLE", s["steps"]["compatibility"].get("verdict") != "VERIFIED COMPATIBLE"),
                    ("validation did not pass", s["steps"]["validation"]["status"] != "passed")) if cond]}
        self.db.execute("UPDATE firmware_upgrade_sessions SET preparation_json=?, executable=? WHERE id=?",
                        (json.dumps(prep, default=str), int(executable and not blocking), sid))
        return self._set_step(sid, "preparation", "failed" if blocking else "passed", **prep)

    # step 6
    def step_execution(self, sid: int, progress=None, cancel=None, fs_probe=None) -> dict:
        s = self._require(sid, "preparation")
        prof = self.profile(s["profile_id"])
        m = METHODS[prof["method"]]
        prep = s["steps"]["preparation"]
        if not s["executable"]:
            res = {"executed": False, "instructions": prep["instructions"],
                   "reason": "; ".join(prep.get("why_not_executable") or ["preparation checks failed"]),
                   "technician_report": True}
            self.db.execute("UPDATE firmware_upgrade_sessions SET execution_json=? WHERE id=?", (json.dumps(res), sid))
            return self._set_step(sid, "execution", "instructions_only", **res)
        fw = self.ctx.library.get(s["target_firmware_id"])
        self.db.execute("UPDATE firmware_upgrade_sessions SET started_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?", (sid,))
        try:
            r: ExecutionResult = m.execute(prof, fw, prep["usb_target"], progress, cancel, fs_probe)
        except InterruptedError as exc:
            self._log(sid, str(exc))
            return self._set_step(sid, "execution", "cancelled", reason=str(exc))
        except Exception as exc:
            self._log(sid, f"Execution failed: {exc}")
            return self._set_step(sid, "execution", "failed", reason=str(exc))
        for line in r.log:
            self._log(sid, line)
        res = {"executed": True, "ok": r.ok, **r.details, "instructions": prep["instructions"],
               "next": "Insert the USB stick into the TV and follow the documented steps. Do not switch off the TV "
                       "while it updates. Then record the result in the verification step."}
        self.db.execute("UPDATE firmware_upgrade_sessions SET execution_json=? WHERE id=?", (json.dumps(res), sid))
        return self._set_step(sid, "execution", "done" if r.ok else "failed", **res)

    # step 7
    def step_verification(self, sid: int, reported_version: str, model_ok: bool, panel_ok: bool | None,
                          boot_ok: bool, functions: dict[str, bool], notes: str = "") -> dict:
        s = self.session(sid)
        if s["steps"]["execution"]["status"] not in ("done", "instructions_only"):
            raise UpgradeBlocked("Execution/instructions step not completed")
        fw = self.ctx.library.get(s["target_firmware_id"])
        expected = fw.version
        run = self.ctx.firmware.latest_run(fw.id)
        if not expected and run:
            vs = [m["value"] for m in self.ctx.firmware.metadata(run["id"]) if m["attribute"] in ("build_id", "firmware_version")
                  and m["confidence"] >= 0.8]
            expected = vs[0] if vs else None
        version_ok = None if not expected else (reported_version.strip().lower() == expected.strip().lower()
                                                or expected.strip().lower() in reported_version.strip().lower())
        failed_funcs = [k for k, v in functions.items() if not v]
        result = {"reported_version": reported_version, "expected_version": expected or "not recorded",
                  "version_check": {True: "matches", False: "DIFFERS", None: "cannot compare (target version unknown)"}[version_ok],
                  "model_ok": model_ok, "panel_ok": panel_ok, "boot_ok": boot_ok, "functions": functions,
                  "failed_functions": failed_funcs, "notes": notes}
        ok = boot_ok and model_ok and version_ok is not False and not failed_funcs and panel_ok is not False
        self.db.execute("UPDATE firmware_upgrade_sessions SET verification_json=?, finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')"
                        " WHERE id=?", (json.dumps(result), sid))
        if ok:
            self.ctx.projects.update(s["project_id"], firmware_version=reported_version)
        return self._set_step(sid, "verification", "passed" if ok else "failed", **result)

    # step 8
    def recovery_guidance(self, sid: int) -> dict:
        s = self.session(sid)
        prof = self.profile(s["profile_id"])
        guide = []
        if prof["recovery_procedure"]:
            guide += [f"Documented recovery ({prof['documentation_ref']}):"] + \
                     [x.strip() for x in prof["recovery_procedure"].splitlines() if x.strip()]
        else:
            guide.append("No recovery procedure is documented in this profile. Contact the manufacturer's service "
                         "channel; do not attempt undocumented flashing.")
        guide.append("Rollback: " + ("documented by the manufacturer for this model — follow the cited procedure."
                                     if prof["rollback_documented"] else
                                     "NOT documented — the previous firmware may not be installable."))
        backup = json.loads(s["backup_json"] or "{}")
        if backup:
            guide.append(f"Saved before upgrade: version {backup.get('original_firmware_version')}; full image: "
                         f"{backup.get('full_firmware_image')}")
        return self._set_step(sid, "recovery", "done", guidance=guide)
