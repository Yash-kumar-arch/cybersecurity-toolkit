from dataclasses import dataclass

@dataclass
class ScannerConfig:
    request_timeout: int = 5
    max_workers: int = 10
    max_pages: int = 25
    user_agent: str = "VulnScanner/1.0"