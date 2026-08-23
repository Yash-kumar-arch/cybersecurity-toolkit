from scanner.scanner import Scanner
from scanner.config import ScannerConfig

from plugins.security_headers import (
    XFOPlugin,
    CSPPlugin,
    HSTSPlugin,
    XCTOPlugin,
    RefPolPlugin
)

from plugins.server_fingerprinting import Server_Fin
from plugins.forms import Forms
from plugins.cookies import Cookie_analysis
from plugins.technology_detection import TechDetection

from plugins.robots import Robot_txt
from plugins.directory_listing import Direct_List
from plugins.backup_files import BackupFile

from reporting.html_report import generate_html_report
import webbrowser
from pathlib import Path

target_url = input("Enter the url: ")

scanner = Scanner(target_url)

# page-level plugins
scanner.add_pages_plugin(XFOPlugin())
scanner.add_pages_plugin(CSPPlugin())
scanner.add_pages_plugin(HSTSPlugin())
scanner.add_pages_plugin(XCTOPlugin())
scanner.add_pages_plugin(RefPolPlugin())
scanner.add_pages_plugin(Server_Fin())
scanner.add_pages_plugin(Forms())
scanner.add_pages_plugin(TechDetection())
scanner.add_pages_plugin(Cookie_analysis())

# domain-level plugins
scanner.add_domain_plugin(Robot_txt(
    target_url,
    scanner.session,
    scanner.config.request_timeout))
scanner.add_domain_plugin(Direct_List(
    target_url,
    scanner.session,
    scanner.config.request_timeout,
    scanner.config.max_workers))
scanner.add_domain_plugin(BackupFile(
    target_url,
    scanner.session,
    scanner.config.request_timeout,
    scanner.config.max_workers))

report = scanner.scan()

generate_html_report(report)

webbrowser.open(
    Path("scan_report.html").resolve().as_uri()
)