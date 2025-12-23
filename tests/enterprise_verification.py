
import os
import sys
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from securecodex.core.engine_v3 import EngineV3
from securecodex.core.sarif_reporter import SARIFReporter

def run_verification():
    print("=== SecureCodeX Enterprise Evolution Verification ===")
    
    # Initialize Engine V3 (points to rules dir)
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'rules'))
    engine = EngineV3(rules_dir)
    engine.db.clear()
    
    # Create test snippets
    test_dir = "temp_verification_project"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        
    snippets = {
        "ai_usage.py": "import openai\nclient = openai.OpenAI()\nresp = client.chat.completions.create(model='gpt-4')",
        "apex_loop.cls": "public class MyClass {\n  public void myMethod() {\n    for(Account a : accounts) {\n      insert a;\n    }\n  }\n}",
        "bash_cat.sh": "cat file.txt | grep 'error'\nfor f in $(ls dir); do echo $f; done",
        "csharp_sqli.cs": "string query = \"SELECT * FROM users WHERE id = \" + id;\nvar cmd = new SqlCommand(query, conn);",
        "c_uaf.c": "int main() {\n  char* buf = malloc(10);\n  free(buf);\n  buf[0] = 'A';\n  return 0;\n}",
        "Dockerfile": "FROM node:latest\nADD . /app\nRUN apt-get upgrade -y"
    }
    
    for filename, content in snippets.items():
        with open(os.path.join(test_dir, filename), 'w') as f:
            f.write(content)
            
    print(f"Scanning {len(snippets)} test files...")
    findings = engine.scan_project(test_dir)
    
    print(f"Found {len(findings)} issues.")
    for f in findings:
        print(f"[{f['severity']}] {f['rule_id']} in {f['file_path']}:{f['line']} - {f['message']}")

    # Generate SARIF report
    reporter = SARIFReporter(test_dir)
    sarif_path = "verification_results.sarif"
    reporter.generate(findings, sarif_path)
    print(f"SARIF report generated at {sarif_path}")

    # Cleanup
    # shutil.rmtree(test_dir) 

if __name__ == "__main__":
    run_verification()
