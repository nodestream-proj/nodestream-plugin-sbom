from enum import Enum
from abc import ABC, abstractmethod
import logging


class SBOMWriter(ABC):
    class NodeLabels(Enum):
        DOCUMENT = "Document"
        COMPONENT = "Component"
        VULNERABILITY = "Vulnerability"
        REFERENCE = "Reference"
        LICENSE = "License"

    class EdgeLabels(Enum):
        DESCRIBES = "DESCRIBES"
        REFERS_TO = "REFERS_TO"
        DEPENDS_ON = "DEPENDS_ON"
        DEPENDENCY_OF = "DEPENDENCY_OF"
        DESCRIBED_BY = "DESCRIBED_BY"
        CONTAINS = "CONTAINS"
        AFFECTS = "AFFECTS"
        LICENSED_BY = "LICENSED_BY"

    def __init__(self, bom: dict) -> None:
        self.bom = bom
        self.logger = logging.getLogger(self.__class__.__name__)
        self.elements = []

    @abstractmethod
    def write_document(self):
        raise NotImplementedError
