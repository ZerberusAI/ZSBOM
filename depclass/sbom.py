from cyclonedx.model import Bom
from cyclonedx.output import get_instance
def generate_sbom(dependencies):
    bom = Bom()
    for dep, ver in dependencies.get("requirements.txt", {}).items():
        bom.add_component({"name": dep, "version": ver, "type": "library"})
    outputter = get_instance(bom, output_format='json')
    with open("sbom.json", "w") as f:
        f.write(outputter.output_as_string())