import logging
from nodestream.pipeline import Extractor
from typing import Iterable
from pathlib import Path
import json
from nodestream_plugin_sbom.utils.spdx_writer import SPDXWriter
from nodestream_plugin_sbom.utils.cyclonedx_writer import CycloneDXWriter
import flatdict


class SBOMExtractor(Extractor):
    def __init__(self, paths: Iterable[Path]) -> None:
        if paths is None:
            raise AttributeError(
                "When using the SBOMExtractor 'paths' is required and cannot be empty"
            )
        p = Path(paths)
        if p.is_dir():
            self.paths = sorted(Path(paths).rglob("*.json"))
        elif p.is_file():
            self.paths = [p]
        self.logger = logging.getLogger(self.__class__.__name__)

    def __clean_dict(self, data: dict) -> dict:
        d = data
        try:
            for key in list(data):
                if isinstance(d[key], list) and len(d[key]) == 0:
                    d.pop(key)
                else:
                    if key.startswith("__"):
                        d.pop(key)
            return dict(flatdict.FlatterDict(d, delimiter=".").items())
        except Exception as e:
            self.logger.error(e)
            return d

    async def extract_records(self):
        for path in self.paths:
            elements = []
            with open(path, "r") as f:
                str = f.read()
                record = json.loads(str)
                if "bomFormat" in record and record["bomFormat"] == "CycloneDX":
                    writer = CycloneDXWriter(record)
                    elements = writer.write_document()
                elif "SPDXID" in record:
                    writer = SPDXWriter(record)
                    elements = writer.write_document()
                else:
                    self.logger.info(
                        f"The file at path {path} is not a valid CycloneDX SBOM"
                    )
                    print(f"The file at path {path} is not a valid CycloneDX SBOM")
            try:
                for e in elements:
                    if e is not None:
                        self.logger.debug(e)
                        if "attributes" in e:
                            e["attributes"] = self.__clean_dict(e["attributes"])
                        yield e
                    else:
                        print(e)
            except Exception as e:
                self.logger.error(e)
