import json
import subprocess
import sys

def run_opa_evaluation():
    cmd = [
        "opa", "eval",
        "--format", "json",
        "--data", "policies/",
        "--input", "infrastructure.json",
        "data.cloud.security.deny"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing OPA CLI: {e.stderr}")
        sys.exit(1)
    
    violations = []
    try:
        # OPA output format nests values inside 'result' -> 'expressions' -> 'value'
        results = output.get("result", [])
        for res in results:
            for expr in res.get("expressions", []):
                val = expr.get("value")
                if isinstance(val, list):
                    for item in val:
                        violations.append(item)
                elif val:
                    violations.append(val)
    except Exception as e:
        print(f"Failed to parse OPA evaluation output: {e}")
        sys.exit(1)
        
    return violations

def generate_sarif_report(violations):
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cloud Security Policy Engine (OPA)",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/open-policy-agent/opa",
                        "rules": [
                            {
                                "id": "CLOUD-SEC-001",
                                "name": "CloudMisconfiguration",
                                "shortDescription": {
                                    "text": "Insecure cloud or data protection configuration detected."
                                }
                            }
                        ]
                    }
                },
                "results": []
            }
        ]
    }

    for violation in violations:
        result_entry = {
            "ruleId": "CLOUD-SEC-001",
            "level": "error",
            "message": {
                "text": violation
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "infrastructure.json"
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }
            ]
        }
        sarif_data["runs"][0]["results"].append(result_entry)

    with open("results.sarif", "w") as f:
        json.dump(sarif_data, f, indent=2)
    
    print(f"SARIF report successfully generated with {len(violations)} findings in 'results.sarif'.")

if __name__ == "__main__":
    violations = run_opa_evaluation()
    generate_sarif_report(violations)
