import argparse
import yaml
from depclass.validate import validate, get_installed_packages
from depclass.sbom import read_json_file, generate_sbom
from depclass.extract import extract_dependencies
from depclass.risk import parse_declared_versions, score_packages_detailed
from depclass.risk_model import load_model

def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def merge_config_and_args(config, args):
    # Override config values with CLI args if provided
    if args.output is not None:
        config["output"]["sbom_file"] = args.output
    return config

def main():
    parser = argparse.ArgumentParser(description="Simple scanning tool")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config YAML")
    parser.add_argument("-o", "--output", help="Output file override")
    parser.add_argument("-sb", "--skip-sbom", help="Skip the SBOM report generation", default=False)

    args = parser.parse_args()

    config = load_config(args.config)
    config = merge_config_and_args(config, args)

    print("=" * 50)
    print("        🔒 ZSBOM Scanner - Powered by Zerberus")
    print("=" * 50 + "\n")


    print(f"Running scan with config: {args.config}")

    results = validate(config)

    declared = parse_declared_versions(extract_dependencies())
    model = load_model(config.get("risk_model"))
    scores = score_packages_detailed(results, declared, get_installed_packages(), model)

    with open(config["output"].get("risk_file", "risk_report.json"), "w") as fp:
        yaml.safe_dump(scores, fp)

    if not args.skip_sbom:
        cve_data = read_json_file("validation_report.json")
        if cve_data:
            generate_sbom(get_installed_packages(), cve_data, config)
