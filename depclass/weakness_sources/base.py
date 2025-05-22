from abc import ABC, abstractmethod
from typing import Dict, List


class WeaknessSource(ABC):
    @abstractmethod
    def fetch_weakness(self) -> Dict:
        pass
