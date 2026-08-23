import requests
from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin
from concurrent.futures import ThreadPoolExecutor


class BackupFile(Plugin):

    def __init__(self,target_url,session,request_timeout,max_workers):
        self.target_url = target_url
        self.request_timeout = request_timeout
        self.max_workers = max_workers
        self.session = session

    def check_backup_file(self, files):

        url = self.target_url + "/" + files
        try:
            response = self.session.get(url,timeout=self.request_timeout)
            if response.status_code == 200:
                return (f"The backup file has discovered at url {url} file_name: {files}")
            else:
                return None

        except requests.exceptions.RequestException:
            return None
        
    def get_paths(self):
        return [
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
    "database.sql", "database.db", "db.sql", "db.tar.gz",
    "config.php.bak", "config.bak", "config.old", "config.backup",
    "index.php.bak", "index.html.bak",
    "site.zip", "site_backup.zip", "website.zip",
    "wp-config.php.bak", "settings.py.bak", ".env.bak",
    "dump.sql", "mysql.sql", "data.sql",
    "old.zip", "archive.zip", "temp.zip",
    "backup_2023.zip", "backup_2024.zip", "backup_2025.zip"
]


    def analyze(self,response):
        findings = []
        score = 0
        max_score = 20

        backup_files = [
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
    "database.sql", "database.db", "db.sql", "db.tar.gz",
    "config.php.bak", "config.bak", "config.old", "config.backup",
    "index.php.bak", "index.html.bak",
    "site.zip", "site_backup.zip", "website.zip",
    "wp-config.php.bak", "settings.py.bak", ".env.bak",
    "dump.sql", "mysql.sql", "data.sql",
    "old.zip", "archive.zip", "temp.zip",
    "backup_2023.zip", "backup_2024.zip", "backup_2025.zip"
]
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(self.check_backup_file, backup_files))

        findings = list(filter(None, results))
        score = len(findings) * 3

        if findings:
            status = "WEAK"

        else:
            status = "OK"

        normalized_score = min((score / max_score),1.0)
        severity = severity_classifer(normalized_score)

        return {
            "path_name":"Backup file discovery",
            "status":status,
            "severity":severity,
            "normalized_score":normalized_score,
            "findings":findings
        }