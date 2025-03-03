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
#### Installation
```sh
git clone https://github.com/ZerberusAI/ZSBOM.git
cd ZSBOM
pip install -r requirements.txt
```

#### Usage
Run individual components:
```sh
python -m depclass.extract  # Extract dependencies
python -m depclass.classify  # Classify dependencies
python -m depclass.validate  # Validate security risks
python -m depclass.sbom      # Generate SBOM
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
   python -m depclass.extract > dependencies.json
   ```
3. Embedding it in a **CI/CD pipeline** (see next section for GitHub Actions workflow).

### 5. How It All Fits Together
1. **Project dependencies are scanned** using ZSBOM.
2. **SBOM files are generated** and stored in the `.dist-info/sboms/` directory.
3. **SBOM metadata is embedded** into `pyproject.toml` to enable automated tracking.
4. **CI/CD pipelines validate dependencies** and security risks before deployment.

### 6. Proposal & Future Enhancements
- **Cross-language dependency detection** (e.g., Rust, C++, JavaScript in Python wheels).
- **Integration with PyPI & Package Managers** (automated SBOM checks for package uploads).
- **Enhanced risk scoring** using CVE tracking and license policy enforcement.

### 7. How to Contribute
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