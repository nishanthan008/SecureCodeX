
import subprocess
import os
import shutil

class RuleSync:
    """
    Synchronizes SecureCodeX with external rule repositories.
    Natively supports cloning and updating the semgrep-rules repo.
    """
    
    SEMGREP_RULES_URL = "https://github.com/semgrep/semgrep-rules.git"
    
    def __init__(self, rules_base_dir: str):
        self.rules_base_dir = rules_base_dir
        self.external_dir = os.path.join(rules_base_dir, "external")
        self.semgrep_dir = os.path.join(self.external_dir, "semgrep-rules")

    def sync_semgrep(self):
        """Clone or update the semgrep-rules repository."""
        if not os.path.exists(self.external_dir):
            os.makedirs(self.external_dir)
            
        if os.path.exists(self.semgrep_dir):
            print(f"Updating semgrep-rules in {self.semgrep_dir}...")
            try:
                subprocess.run(["git", "-C", self.semgrep_dir, "pull"], check=True)
            except Exception as e:
                print(f"Failed to pull semgrep-rules: {e}")
        else:
            print(f"Cloning semgrep-rules to {self.semgrep_dir}...")
            try:
                subprocess.run(["git", "clone", "--depth", "1", self.SEMGREP_RULES_URL, self.semgrep_dir], check=True)
            except Exception as e:
                print(f"Failed to clone semgrep-rules: {e}")

    def cleanup_external(self):
        """Remove external rules directory."""
        if os.path.exists(self.external_dir):
            shutil.rmtree(self.external_dir)
