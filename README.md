# ZSBOM

## Zerberus SBOM Automation Framework

### 1. Intent & Purpose
ZSBOM is an open-source framework designed to automate **dependency classification, validation, and SBOM (Software Bill of Materials) generation**. The purpose of this project is to help developers, security teams, and DevOps engineers:
- Extract dependencies from Python projects.
- Classify them based on open-source licensing, security risks, and direct vs transitive relationships.
- Generate industry-standard SBOMs in **CycloneDX** and **SPDX** formats.
- Validate dependencies against **security vulnerabilities (CVEs)**, **license compliance**, and **best practices**.
- Seamlessly integrate dependency tracking into **CI/CD pipelines**.

### 2. Terminology
This repository follows the terminology defined in the **Python Packaging User Guide Glossary**. Non-Python package users should note that some terminology may differ from other software ecosystems.

### 3. Motivation
#### **Regulations & Compliance**
SBOMs are essential for tracking software composition and are increasingly required under software security regulations such as:
- **Secure Software Development Framework (SSDF)**
- **Cyber Resilience Act (CRA)**
- **NIST Cybersecurity Framework (CSF)**
- **NTIA Minimum Elements for an SBOM (CISA)**

#### **Phantom Dependencies & Security Risks**
Python packages often bundle non-Python dependencies (C/C++, Rust, Fortran, JavaScript, etc.), making **Software Composition Analysis (SCA)** challenging. ZSBOM aims to:
- Identify **hidden dependencies** that aren't explicitly listed.
- Ensure accurate **security risk assessment** of dependencies.

### 4. How to Use ZSBOM in Your Project
#### Installation Options

##### For General Users (Recommended CLI Usage)
To install ZSBOM as a command-line tool from GitHub:
```sh
pip install git+https://github.com/ZerberusAI/ZSBOM.git
```

After installation, you can run ZSBOM directly from your terminal:

```sh
zsbom --help
zsbom
```

#### For local development
```sh
git clone https://github.com/ZerberusAI/ZSBOM.git
cd ZSBOM
pip install .
```

#### Integrating with a Project
You can **integrate ZSBOM** into your existing Python project by:
1. Importing it as a module:
   ```python
   from depclass.extract import extract_dependencies
   deps = extract_dependencies()
   print(deps)
   ```
2. Running it as a standalone CLI tool:
   ```sh
   zsbom
   ```
3. Embedding it in a **CI/CD pipeline** (see next section for GitHub Actions workflow).

### 5. How It All Fits Together
1. **Project dependencies are scanned** using ZSBOM.
2. **SBOM files are generated** and stored in the project root directory `sbom.json`.
3. **SBOM metadata is embedded** into `pyproject.toml` to enable automated tracking.
4. **CI/CD pipelines validate dependencies** and security risks before deployment.
5. **Packages are scored across five metadata dimensions** (version drift, known CVEs, CWE mappings, abandonment, typosquatting) to classify their risk level. Scoring weights are configurable via the `risk_model` section of `config.yaml`.

### 6. CI/CD Integration Example (GitHub Actions)
This section provides an example of how to integrate ZSBOM into a GitHub Actions workflow to automatically scan your project on pull requests to the `main` branch.

#### GitHub Actions Workflow
Create a file named `.github/workflows/zsbom_scan.yml` (or any other `.yml` file) in your project's repository with the following content:

```yaml
name: PR ZSBOM Scan

on:
  pull_request:
    branches: ["main"]

permissions:
  contents: read          # Required to checkout the repository
  # pull-requests: write # Uncomment if you plan to add PR comments with scan results

jobs:
  zsbom-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.9' # Adjust to your project's Python version

      - name: Install project dependencies
        run: |
          python -m pip install --upgrade pip
          # This step installs dependencies for YOUR project.
          # Modify it according to your project's dependency management.
          if [ -f requirements.txt ]; then
            echo "Installing project dependencies from requirements.txt"
            pip install -r requirements.txt
          elif [ -f pyproject.toml ]; then # Assumes setuptools/build or similar PEP 517 build backend
            echo "Installing project dependencies using pip from pyproject.toml"
            pip install . # This will install the package defined by pyproject.toml
          # Example for Poetry (if poetry.lock exists and you use Poetry):
          # elif [ -f pyproject.toml ] && [ -f poetry.lock ]; then
          #   echo "Installing project dependencies using Poetry"
          #   pip install poetry
          #   poetry install --no-dev # Or poetry install if dev dependencies are needed for the scan
          else
            echo "No primary dependency file (requirements.txt or pyproject.toml for pip installable package) found for the project."
            # Consider failing the job if dependencies are crucial for an accurate scan
            # exit 1
          fi

      - name: Install ZSBOM
        run: |
          # Installs the latest version of ZSBOM CLI from its GitHub repository
          pip install git+https://github.com/ZerberusAI/ZSBOM.git

      - name: Run ZSBOM scan
        run: |
          # This command runs ZSBOM.
          # It assumes a 'config.yaml' for ZSBOM exists in your repository root,
          # or ZSBOM's default configuration is sufficient for your needs.
          # You might need to specify a config file, e.g.:
          # zsbom --config path/to/your/zsbom_config.yaml
          # Ensure your ZSBOM configuration outputs to 'sbom.json' (or adjust the artifact path below).
          zsbom

      - name: Upload ZSBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-json
          path: sbom.json # This should match the output file path configured in ZSBOM
          if-no-files-found: error # Optional: Fails the step if sbom.json is not found
```

#### Workflow Explanation:
- Trigger: This workflow runs on every pull request targeting the main branch.
- Permissions: It needs contents: read to check out your code. If you want the workflow to comment on PRs (e.g., with a summary or link to the SBOM), you'd uncomment pull-requests: write.
- Python Setup: It sets up a specified Python version. Adjust '3.9' as needed.
- Install Project Dependencies: This crucial step installs the dependencies of the project being scanned. You'll likely need to customize this block based on whether your project uses requirements.txt, pyproject.toml (with pip install .), Poetry, or another package manager.
- Install ZSBOM: It installs the ZSBOM tool directly from its GitHub repository.
- Run ZSBOM Scan: This executes ZSBOM. By default, it might look for a config.yaml in the root of your project. You can customize the command to point to a specific configuration file. Ensure this configuration directs output to sbom.json.
- Upload Artifact: The generated sbom.json file is uploaded as an artifact, allowing you to download and inspect it after the workflow run.
This workflow provides a basic template. You can expand it to include steps like failing the build on critical vulnerabilities (if ZSBOM supports such exit codes and reporting), or integrating with other security tools.

### 7. Proposal & Future Enhancements
- **Cross-language dependency detection** (e.g., Rust, C++, JavaScript in Python wheels).
- **Integration with PyPI & Package Managers** (automated SBOM checks for package uploads).
- **Enhanced risk scoring** using CVE tracking and license policy enforcement.
- **Multithreading** for improved performance.
- **Pagination for OSV API results** to handle large datasets.
- Implement logic to **fetch fresh package data from source if changes are detected**, bypassing cache.
- Refine **severity scoring for vulnerabilities**.
- Add capability for **container image scanning**.
- Develop **full offline support** using a local vulnerability database.
- Implement **isolated package installation** for ZSBOM and the project it scans, to avoid conflicts.

### 8. How to Contribute
We welcome contributions from the open-source community! To contribute:
#### Steps to Get Started:
1. **Fork the Repository**: Click the 'Fork' button at the top right of [ZSBOM GitHub Repo](https://github.com/ZerberusAI/ZSBOM).
2. **Clone Your Fork**:
   ```sh
   git clone https://github.com/yourusername/ZSBOM.git
   cd ZSBOM
   ```
3. **Create a Branch**:
   ```sh
   git checkout -b feature-branch
   ```
4. **Make Your Changes & Commit**:
   ```sh
   git add .
   git commit -m "Added new classification logic"
   ```
5. **Push to GitHub**:
   ```sh
   git push origin feature-branch
   ```
6. **Submit a Pull Request (PR)**: Open a PR from your forked repo to the main **ZSBOM** repository.

#### Contribution Guidelines:
- Follow **PEP 8** coding standards.
- Ensure unit tests are added (`pytest` recommended).
- Provide clear commit messages and documentation updates.
- If adding a new feature, ensure it integrates well with **SBOM formats (CycloneDX/SPDX)**.