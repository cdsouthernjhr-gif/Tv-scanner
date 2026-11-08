import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import firmware_builders as fb
from app.modules.software_analyzer import connectors as dev
from app.modules.software_analyzer import inventory as inv
from app.services.project_service import TVProject
from synthetic_datasheets import make_datasheet


# ---- extracted-tree fixture ------------------------------------------------------------------------
def make_tree(root: Path) -> list[str]:
    files = {
        "sys/system/build.prop": "ro.build.version.release=11\n",
        "sys/system/app/YouTube/YouTube.apk": "apk",
        "sys/system/priv-app/TvSettings/TvSettings.apk": "apk",
        "sys/system/etc/permissions/tv_core_hardware.xml": '<permissions><feature name="android.software.leanback"/></permissions>',
        "sys/system/lib/libc.so": "x", "sys/system/lib/libssl.so.1.1": "x", "sys/system/lib/libssl.so": "x",
        "sys/vendor/lib/modules/8821cu.ko": "x", "sys/vendor/lib/modules/mtk_drm.ko": "x",
        "sys/vendor/lib/modules/snd_soc_tas5805.ko": "x", "sys/vendor/lib/modules/sample.ko": "x",
        "sys/vendor/lib/modules/btmtk_usb.ko": "x",
        "sys/vendor/etc/init/net.rc": "service dhcp /system/bin/dhcpcd eth0\n setprop wifi.interface wlan0\n",
        "sys/vendor/config/panel/panel_4k.ini": "PanelName = LC550EGE\nm_wPanelWidth = 3840\nm_wPanelHeight = 2160\nVByOne = 1\n",
        "sys/vendor/etc/audio_effects.conf": "sample_rate = 48000\nchannels = 2\n",
        "web/usr/palm/applications/com.webos.app.browser/appinfo.json":
            json.dumps({"id": "com.webos.app.browser", "title": "Web Browser", "version": "3.1.0"}),
    }
    for rel, txt in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt)
    return sorted(files)


def test_inventory_extracts_apps_libs_drivers_configs(tmp_path):
    files = make_tree(tmp_path)
    apps = {i.name: i for i in inv.applications(files, tmp_path)}
    assert {"YouTube", "TvSettings", "com.webos.app.browser"} <= set(apps)
    assert "3.1.0" in apps["com.webos.app.browser"].value
    libs = {i.name: i.value for i in inv.libraries(files)}
    assert libs["libssl"] == "1.1" and libs["libc"] == "version not in file name"
    drv = {i.name: i.value for i in inv.drivers(files)}
    assert drv["8821cu.ko"].startswith("wifi") and drv["mtk_drm.ko"].startswith("display")
    assert drv["snd_soc_tas5805.ko"].startswith("audio") and drv["btmtk_usb.ko"].startswith("bluetooth")
    assert drv["sample.ko"].startswith("other")              # no substring false positive ('amp' in 'sample')
    cf = inv.config_facts(files, tmp_path)
    assert {i.name for i in cf if i.category == "network_interface"} == {"eth0", "wlan0"}
    disp = {i.name: i.value for i in cf if i.category == "display"}
    assert disp["m_wPanelWidth"] == "3840" and disp["PanelName"] == "LC550EGE"
    assert {i.name for i in cf if i.category == "audio"} >= {"sample_rate", "channels"}


def test_fingerprint_rules(tmp_path):
    files = make_tree(tmp_path)
    found = {i.name: i for i in inv.fingerprint(files, tmp_path, {"webOS"}, {}, set())}
    assert found["Android"].confidence >= 0.85 and "build.prop" in found["Android"].value
    assert "leanback" in found["Android TV"].value
    assert "webOS" in found                                     # /usr/palm + keyword
    only_kw = {i.name: i for i in inv.fingerprint([], tmp_path, {"Tizen"}, {}, set())}
    assert only_kw["Tizen"].confidence == 0.4                   # keyword alone stays weak
    no_android = {i.name for i in inv.fingerprint(["x/tv_core_hardware.xml"], tmp_path, set(), {}, set())}
    assert "Android TV" not in no_android                       # requires Android evidence


# ---- analyzer ------------------------------------------------------------------------------------------
def test_software_analysis_end_to_end(ctx, tmp_path, sample_image):
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme", model_number="TESTTV55"))
    f = tmp_path / "fw.bin"
    fb.composite(f)
    rec = ctx.library.import_file(f, project_id=p.id)
    ctx.firmware.analyze(rec.id, use_binwalk=False)
    ev = ctx.evidence.add_image(p.id, sample_image, "system_info_menu")
    ctx.db.execute("UPDATE scan_evidence SET ocr_text=? WHERE id=?",
                   ("Software Version: T-KTM2AKUC-1500.5\nAndroid TV OS version 11\nKernel: 4.19.116\n"
                    "Wired MAC address: 00:11:22:33:44:55\nResolution 3840x2160", ev.id))
    ctx.software.add_operator_fact(p.id, "build", "RTM-2026.03", None, "Settings > About > Build")
    with pytest.raises(ValueError):
        ctx.software.add_operator_fact(p.id, "build", "x", None, "")
    s = ctx.software.analyze(p.id)
    vals = lambda cat: {v["value"] for v in s[cat]}      # noqa: E731
    assert "Android" in vals("os") and s["os_best"] == "Android"
    assert {"Android 9", "Android 11"} <= vals("os_version")       # firmware vs. menu photo (different sources)
    assert {"4.9.118", "4.19.116"} <= vals("kernel")
    assert "T-KTM2AKUC-1500.5" in vals("firmware_version") and "RTM-2026.03" in vals("build")
    assert any(v.startswith("U-Boot 2015.04") for v in vals("bootloader"))
    ocr = [f for f in ctx.software.facts(p.id) if f["source_type"] == "system_menu_ocr"]
    assert {f["category"] for f in ocr} >= {"firmware_version", "os_version", "kernel", "device_info", "display"}
    # re-analysis keeps operator facts, does not duplicate firmware facts
    n = len(ctx.software.facts(p.id))
    ctx.software.analyze(p.id)
    assert len(ctx.software.facts(p.id)) == n
    ctx.software.add_operator_fact(p.id, "os", "Tizen", None, "photo of boot screen")
    assert ctx.software.summary(p.id)["conflicts"]


# ---- connectors -------------------------------------------------------------------------------------------
DESC = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>Living Room TV</friendlyName>
<manufacturer>Acme</manufacturer><modelName>TESTTV55</modelName><modelNumber>55X</modelNumber>
<serialNumber>SN123</serialNumber><UDN>uuid:abc</UDN></device></root>"""


@pytest.fixture
def desc_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(DESC.encode())

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/desc.xml"
    srv.shutdown()


class FakeSock:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def settimeout(self, t): pass

    def setsockopt(self, *a): pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, n):
        if self.replies:
            return self.replies.pop(0)
        import socket
        raise socket.timeout()

    def close(self): pass


def _ssdp(loc):
    return (f"HTTP/1.1 200 OK\r\nLOCATION: {loc}\r\nSERVER: Linux/4.9 UPnP/1.0 Acme/1.0\r\nST: upnp:rootdevice\r\n"
            f"USN: uuid:abc::upnp:rootdevice\r\n\r\n").encode()


def test_ssdp_parsing_and_lan_only():
    assert dev.parse_ssdp_response(_ssdp("http://192.168.1.5/d.xml"))["LOCATION"] == "http://192.168.1.5/d.xml"
    assert dev.parse_device_description(DESC)["modelName"] == "TESTTV55"
    sock = FakeSock([(_ssdp("http://192.168.1.5:8080/d.xml"), ("192.168.1.5", 1900)),
                     (_ssdp("http://8.8.8.8/evil.xml"), ("8.8.8.8", 1900)),            # public: ignored
                     (_ssdp("http://192.168.1.9/x.xml"), ("192.168.1.5", 1900))])     # host mismatch: ignored
    devs = dev.ssdp_discover(0.3, sock_factory=lambda: sock)
    assert [d.location for d in devs] == ["http://192.168.1.5:8080/d.xml"]
    assert b"M-SEARCH" in sock.sent[0][0] and sock.sent[0][1] == dev.SSDP_ADDR
    with pytest.raises(ValueError):
        dev.fetch_description("http://93.184.216.34/desc.xml")


def test_upnp_discover_and_link(ctx, desc_server):
    p = ctx.projects.create(TVProject(name="t"))
    with pytest.raises(dev.NotAuthorized):
        ctx.software.upnp_discover("")
    sock = FakeSock([(_ssdp(desc_server), ("127.0.0.1", 1900))])
    devs = ctx.software.upnp_discover("Own TV, owner present", 0.3, sock_factory=lambda: sock)
    assert devs[0]["manufacturer"] == "Acme" and devs[0]["serialNumber"] == "SN123"
    ctx.software.record_upnp_device(p.id, devs[0], "Own TV, owner present")
    names = {f["name"] for f in ctx.software.facts(p.id, "device_info")}
    assert {"manufacturer Acme", "model name TESTTV55", "serial number SN123"} <= names
    assert ctx.software.device_sessions(p.id)[0]["authorization_note"] == "Own TV, owner present"


def _fake_adb(tmp_path, unauthorized=False):
    if os.name == "nt":
        pytest.skip("fake adb uses a POSIX shell script")
    py = tmp_path / "fake_adb.py"
    py.write_text(
        "import sys\n"
        f"if {unauthorized}:\n    sys.stderr.write('error: device unauthorized'); sys.exit(1)\n"
        "a = ' '.join(sys.argv[3:])\n"
        "out = {'shell getprop': '[ro.build.version.release]: [11]\\n[ro.product.model]: [TESTTV55]\\n[ro.build.display.id]: [RTM.2026]',\n"
        "       'shell uname -a': 'Linux localhost 4.19.116-g1 #1 SMP PREEMPT armv8l',\n"
        "       'shell pm list packages -s': 'package:com.android.tv.settings\\npackage:com.google.android.youtube.tv',\n"
        "       'shell pm list packages -3': 'package:com.example.app',\n"
        "       'shell pm list features': 'feature:android.software.leanback',\n"
        "       'shell wm size': 'Physical size: 3840x2160',\n"
        "       'shell ip -brief address': 'lo UNKNOWN 127.0.0.1/8\\neth0 UP 192.168.1.50/24\\nwlan0 DOWN',\n"
        "       'shell cat /proc/modules': '8821cu 2000 0 - Live 0x0\\nmtk_drm 100 0 - Live 0x0'}\n"
        "print(out.get(a, ''))\n")
    w = tmp_path / "adb"
    w.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py}" "$@"\n')
    w.chmod(w.stat().st_mode | stat.S_IEXEC)
    return str(w)


def test_adb_read_only_collection(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="t"))
    adb = _fake_adb(tmp_path)
    with pytest.raises(ValueError, match="not an allowed"):
        dev.adb_query(adb, "192.168.1.50:5555", ["reboot"])
    with pytest.raises(ValueError, match="LAN"):
        dev.adb_query(adb, "8.8.8.8:5555", ["kernel"])
    ctx.software.adb_collect(p.id, "192.168.1.50:5555", "Owner's TV, debugging enabled by owner", adb)
    f = ctx.software.facts(p.id)
    by = lambda cat: {x["name"] for x in f if x["category"] == cat}    # noqa: E731
    assert {"Android", "Android TV"} <= by("os") and "Android 11" in by("os_version")
    assert "4.19.116-g1" in by("kernel") and "com.example.app" in by("application")
    assert "resolution 3840x2160" in by("display") and by("network_interface") == {"eth0", "wlan0"}
    assert {"8821cu", "mtk_drm"} <= by("driver")
    assert all(x["source_type"] == "adb" for x in f)


def test_adb_unauthorized_device(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="t"))
    with pytest.raises(dev.NotAuthorized, match="accept the prompt"):
        ctx.software.adb_collect(p.id, "SERIAL123", "Owner's TV, owner present", _fake_adb(tmp_path, True))


# ---- service menu database ------------------------------------------------------------------------------
REC = {"manufacturer": "Acme", "model_pattern": "TESTTV*", "chassis": "CH-9", "menu_category": "Service Menu",
       "access_procedure": "Press MENU, 1, 1, 4, 7 on the service remote (as per manual)",
       "function_description": "White balance and option codes", "access_availability": "service remote required",
       "official_documentation": "Acme CH-9 Service Manual rev.2, section 4.2", "configuration_risk": "high",
       "backup_mechanism": "Export settings to USB via Service Menu > Data > Backup"}


def test_service_menu_validation(ctx):
    S = ctx.service_menus
    with pytest.raises(ValueError, match="official_documentation"):
        S.add({**REC, "official_documentation": None})
    with pytest.raises(ValueError, match="menu_category"):
        S.add({**REC, "menu_category": "Secret Menu"})
    for bad in ("Brute force the PIN 0000-9999", "try all passwords from the list", "bypass the password prompt"):
        with pytest.raises(ValueError, match="not accepted"):
            S.add({**REC, "access_procedure": bad})
    with pytest.raises(ValueError, match="document #"):
        S.add({**REC, "document_id": 999})


def test_service_menu_applicable_and_import_export(ctx, tmp_path):
    S = ctx.service_menus
    rid = S.add(REC)
    S.add({**REC, "model_pattern": "OTHER*", "menu_category": "Hotel Mode"})
    S.add({**REC, "model_pattern": None, "chassis": None, "menu_category": "Official Factory Reset Documentation",
           "configuration_risk": "medium"})
    p = ctx.projects.create(TVProject(name="t", manufacturer="ACME", model_number="testtv55", chassis="ch-9"))
    app = S.applicable(p)
    assert [r["id"] for r in app][0] == rid and len(app) == 2
    assert "model testtv55 matches TESTTV*" in app[0]["applies_because"]
    assert S.applicable(ctx.projects.create(TVProject(name="u"))) == []
    js, cs = tmp_path / "m.json", tmp_path / "m.csv"
    assert S.export_json(js) == 3 and S.export_csv(cs) == 3
    data = json.loads(js.read_text())
    data["records"].append({**REC, "official_documentation": ""})          # undocumented → rejected
    js.write_text(json.dumps(data))
    ok, rej = S.import_file(js)
    assert ok == 3 and len(rej) == 1 and "official_documentation" in rej[0]
    ok, rej = S.import_file(cs)
    assert ok == 3 and rej == []


def test_service_manual_passages_and_document_link(ctx, tmp_path):
    pdf = make_datasheet(tmp_path / "sm.pdf", "Acme CH-9 Service Manual", [
        ["Safety precautions", "Disconnect mains before servicing"],
        ["4.2 Entering Service Mode", "Press MENU then 1 1 4 7 on the service remote.", "Factory reset: Option > Reset"]])
    did = ctx.datasheets.import_pdf(pdf, vendor="Acme")
    hits = ctx.service_menus.find_passages(did)
    assert {(h["page"], h["keyword"]) for h in hits} >= {(2, "service mode"), (2, "service remote"), (2, "factory reset")}
    rid = ctx.service_menus.add({**REC, "official_documentation": None, "document_id": did, "document_page": 2})
    assert ctx.service_menus.get(rid)["official_documentation"] == "Acme CH-9 Service Manual, p.2"


def test_service_action_workflow(ctx):
    S = ctx.service_menus
    rid = S.add(REC)
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme", model_number="TESTTV55", chassis="CH-9"))
    aid = S.plan_action(p.id, rid, "Panel option code", "12", "replacement panel fitted", old_value="11")
    assert S.action(aid)["backup_required"] == 1
    with pytest.raises(ValueError, match="backup"):
        S.confirm(aid, S.confirmation_phrase(aid))
    with pytest.raises(ValueError, match="confirmed"):
        S.mark_performed(aid, "done")
    S.record_backup(aid, "settings exported to USB: acme_backup_0811.dat")
    with pytest.raises(ValueError, match="Type exactly"):
        S.confirm(aid, "yes")
    S.confirm(aid, "CHANGE Panel option code")
    S.mark_performed(aid, "picture correct after change")
    a = S.action(aid)
    assert a["status"] == "performed" and a["confirmed_by"] and a["performed_at"]
    with pytest.raises(ValueError):
        S.cancel(aid)
    with pytest.raises(ValueError, match="referenced"):
        S.delete(rid)
    acts = [e["action"] for e in ctx.audit.entries("tv_project", p.id)]
    assert {"service_action.plan", "service_action.backup", "service_action.confirm",
            "service_action.performed"} <= set(acts)
    # without a documented backup mechanism confirmation is possible straight away
    rid2 = S.add({**REC, "backup_mechanism": None, "menu_category": "Picture Settings"})
    aid2 = S.plan_action(p.id, rid2, "Backlight", "80", "customer request")
    S.confirm(aid2, "CHANGE Backlight")
    assert S.action(aid2)["status"] == "confirmed"


def test_os_and_service_reports(ctx, tmp_path):
    from pypdf import PdfReader
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme", model_number="TESTTV55", chassis="CH-9"))
    ctx.software.add_operator_fact(p.id, "os", "Android TV", None, "Settings > About")
    ctx.software.add_operator_fact(p.id, "kernel", "4.19.116", None, "Settings > About")
    rid = ctx.service_menus.add(REC)
    ctx.service_menus.plan_action(p.id, rid, "Panel option code", "12", "replacement panel")
    R = ctx.software_reports
    t = " ".join(pg.extract_text() for pg in PdfReader(R.os_report_pdf(p.id)).pages)
    assert "Operating System Report" in t and "Android TV" in t and "not determined" in t
    assert json.loads(R.os_report_json(p.id).read_text())["summary"]["os_best"] == "Android TV"
    t2 = " ".join(pg.extract_text() for pg in PdfReader(R.service_report_pdf(p.id)).pages)
    assert "Service Menu Report" in t2 and "Service Manual rev.2" in t2 and "Panel option code" in t2
