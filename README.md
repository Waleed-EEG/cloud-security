# Cloud Security Misconfiguration Detection (OPA + SARIF)

An automated **Policy-as-Code** security pipeline that validates cloud configurations for data-protection and compliance risks using **Open Policy Agent (OPA)**, translating findings into **SARIF** and surfacing them directly inside **GitHub Actions CI/CD** before deployment.

---

## Architecture Overview

```text
[ Infrastructure Code ] ──> [ GitHub Actions CI/CD ] ──> [ Open Policy Agent (Rego) ]
                                                                      │
                                                                      ▼
[ GitHub Code Scanning ] <── [ SARIF Report ] <── [ Python Translation Layer ]
```

---

## Project Directory Structure

```text
cloud-security-demo/
├── .github/
│   └── workflows/
│       └── security-scan.yml
├── policies/
│   └── s3_security.rego
├── scripts/
│   └── opa_to_sarif.py
├── infrastructure.json
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.x
- Open Policy Agent (OPA) CLI

### Install OPA (Ubuntu / Linux)

```bash
curl -L -o opa https://openpolicyagent.org/downloads/v0.61.0/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/opa
```

---

## Running the Scan Locally

1. Clone or set up the repository locally.
2. Ensure your target infrastructure configuration is defined in `infrastructure.json`.
3. Execute the Python translation script to run OPA evaluations and generate the SARIF report:

   ```bash
   python3 scripts/opa_to_sarif.py
   ```

4. Check the generated `results.sarif` file for structured security findings.

---

## GitHub Actions CI/CD Automation

The pipeline runs automatically on every push or pull request to the `main` or `master` branches.

1. Checks out the repository code.
2. Installs the OPA CLI runner.
3. Executes the policy evaluation script (`scripts/opa_to_sarif.py`).
4. Uploads the resulting `results.sarif` report natively to the **GitHub Security → Code Scanning** dashboard.
