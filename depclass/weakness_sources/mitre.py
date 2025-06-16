import io
import logging
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, List

import requests
from depclass.weakness_sources.base import WeaknessSource
import traceback


class MitreSource(WeaknessSource):

    def __init__(self, config: dict, cache):
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(__name__)
        self.api_url = config['sources']['cwe']['mitre_weaknesses']['url']
    
    def get_from_source(self):
        root = None
        response = requests.get(
            self.api_url,
            stream=True,
            timeout=30,
            headers={
                'User-Agent': 'ZSBOM-SecurityScanner/1.0',
                'Accept': 'application/zip'
            }
        )
        response.raise_for_status()

        # Process zip file directly from memory
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            xml_files = [f for f in zip_file.namelist() if f.endswith('.xml')]
            if not xml_files:
                raise ValueError("No XML file found in ZIP archive")
            
            with zip_file.open(xml_files[0]) as xml_file:
                tree = ET.parse(xml_file)
                root = tree.getroot()
        
        return root
    
    def fetch_weakness(self) -> Dict:
        try:
            data = {}
            if self.config['caching']['enabled']:
                cached_data = self.cache.get_cached_data('mitre_cwe', self.config['caching']['ttl_hours'])
                if cached_data:
                    self.logger.info("✅ Using MITRE cached CWE data")
                    return cached_data
            
            root = self.get_from_source()

            ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
            for weakness in root.findall('.//cwe:Weakness', ns):
                cwe_id = weakness.get('ID')
                name = weakness.get('Name')
                desc_node = weakness.find('cwe:Description', ns)

                if not cwe_id or not name:
                    continue

                description = desc_node.text.strip() if desc_node is not None else ""

                data[int(cwe_id)] = {
                    "id": f"CWE-{cwe_id}",
                    "name": name,
                    "description": description
                }
            
            if data:
                self.logger.info(f"✅ Successfully parsed {len(data)} CWE entries from MITRE")
                if self.config['caching']['enabled']:
                    self.cache.cache_data('mitre_cwe', data)

            return data
        except Exception as e:
            traceback.print_exc()
            logging.error(f"⚠️ MITRE CWE fetches failed: {e}")
            raise Exception from e

        
