import io
import logging
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, List

import requests
from depclass.weakness_sources.base import WeaknessSource


class NvdSource(WeaknessSource):

    def __init__(self, config: dict, cache):
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(__name__)
        self.api_url = config['sources']['cwe']['nvd_weaknesses']['url']
    
    def get_from_source(self):
        response = requests.get(
            self.api_url,
            timeout=30,
            headers={
                'User-Agent': 'ZSBOM-SecurityScanner/1.0',
                'Accept': 'application/json'
            }
        )
        response.raise_for_status()

        return response.json()
    
    def fetch_weakness(self) -> Dict:
        try:
            data = {}
            if self.config['caching']['enabled']:
                cached_data = self.cache.get_cached_data('nvd_cwe', self.config['caching']['ttl_hours'])
                if cached_data:
                    self.logger.info("✅ Using NVD cached CWE data")
                    return cached_data
            
            json_data = self.get_from_source()

            for item in json_data.get("CWE", []):
                cwe_id = item.get("cweId")
                if cwe_id:
                    data[int(cwe_id.split('-')[1])] = {
                        "id": cwe_id,
                        "name": item.get("name"),
                        "description": item.get("description")
                    }

            self.logger.info("✅ Successfully fetched NVD CWE data")
            
            
            if data:
                self.logger.info(f"✅ Successfully parsed {len(data)} CWE entries from NVD")
                if self.config['caching']['enabled']:
                    self.cache.cache_data('nvd_cwe', data)

            return data
        except Exception as e:
            logging.error(f"⚠️ NIST CWE fetches failed: {e}")
            raise Exception from e

        
