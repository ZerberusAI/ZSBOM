#REvised Location Updated as Per CycloneDX @ https://cyclonedx-python-library.readthedocs.io/en/stable/autoapi/cyclonedx/model/bom/ 
from cyclonedx.model.bom import Bom
from cyclonedx.output import get_instance, OutputFormat
from cyclonedx.model.component import Component, ComponentType

def generate_sbom(dependencies):
    bom = Bom()
    for dep, ver in dependencies.get("requirements.txt", {}).items():
        component = Component(name=dep, version=ver, type=ComponentType.LIBRARY)
        bom.components.add(component)
    
    outputter = get_instance(bom=bom, output_format=OutputFormat.JSON)
    
    with open("sbom.json", "w") as f:
        f.write(outputter.output_as_string())
# Old version - retained here for Historical debugging reasons
# from cyclonedx.model import Bom
# from cyclonedx.output import get_instance
# def generate_sbom(dependencies):
#    bom = Bom()
#    for dep, ver in dependencies.get("requirements.txt", {}).items():
#        bom.add_component({"name": dep, "version": ver, "type": "library"})
#    outputter = get_instance(bom, output_format='json')
#    with open("sbom.json", "w") as f:
#        f.write(outputter.output_as_string())
