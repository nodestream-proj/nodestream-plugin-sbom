import uuid
from typing import Iterable
from .sbom_writer import SBOMWriter


class CycloneDXWriter(SBOMWriter):
    def write_document(self) -> Iterable:
        """Writes the CycloneDX document

        Args:
            bom (dict): The dict of the CycloneDX document

        Returns:
            bool: True if successful, False if not
        """
        try:
            self.logger.info("Writing bom metadata")
            self.__write_bom(self.bom)

            if "components" in self.bom:
                self.__write_components(self.bom["components"])

            if "dependencies" in self.bom:
                self.__write_dependencies(self.bom["dependencies"])

            if "vulnerabilities" in self.bom:
                self.__write_vulnerabilities(self.bom["vulnerabilities"])

            return self.elements
        except Exception as e:
            self.logger.error(e)
            raise e

    def __write_bom(self, bom):
        """Writes the BOM metadata

        Args:
            bom (str): The string of the CycloneDX document

        Returns:
            dict: The document
        """
        if "serialNumber" in bom:
            document_id = f"{self.NodeLabels.DOCUMENT.value}_{bom['serialNumber']}"
        else:
            document_id = f"{self.NodeLabels.DOCUMENT.value}_{uuid.uuid4()}"

        if "metadata" in bom and "component":
            attr = {**bom, **bom["metadata"]}
            del attr["metadata"]
        else:
            attr = {**bom}

        document = {
            "attributes": attr,
            "__type": self.NodeLabels.DOCUMENT.value,
            "__document_id": document_id,
        }

        if "component" in document["attributes"]:
            self.__write_components([document["attributes"]["component"]])

        document["describes"] = []
        for c in document["attributes"]["components"]:
            document["describes"].append(
                {
                    "__toId": f"{self.NodeLabels.COMPONENT.value}_{c['type']}_{c['name']}",
                }
            )

        self.__remove_attributes_key(document, "component")
        self.__remove_attributes_key(document, "components")
        self.__remove_attributes_key(document, "dependencies")
        self.__remove_attributes_key(document, "vulnerabilities")

        # Do mappings from Cyclone DX to more generic name
        if "metadata" in document and "timestamp" in document["metadata"]:
            document["created_timestamp"] = document["metadata"]["timestamp"]

        self.elements.append(document)

    def __write_license(self, licenses: list, toId: str):
        """Writes the licenses of the BOM to the graph

        Args:
            licenses (list): The licenses to write
            toId (dict): The entity to link the licenses to
        """
        try:
            for lic in licenses:
                if "license" in lic:
                    if "id" in lic["license"]:
                        license = {
                            "attributes": {**lic["license"]},
                            "__type": self.NodeLabels.LICENSE.value,
                            "__license_id": f"{self.NodeLabels.LICENSE.value}_{str(lic['license']['id']).lower()}",
                        }
                        license["attributes"]["name"] = license["attributes"].pop("id")
                    elif "name" in lic["license"]:
                        license = {
                            "attributes": {**lic["license"]},
                            "__type": self.NodeLabels.LICENSE.value,
                            "__license_id": f"{self.NodeLabels.LICENSE.value}_{str(lic['license']['name']).lower()}",
                        }
                    else:
                        self.logger.info(
                            f"Skipping License nodes due to no id or name for {lic}"
                        )
                    license["licensed_by"] = [
                        {
                            "__toId": toId,
                        }
                    ]
                    self.elements.append(license)
                else:
                    self.logger.info("Skipping License nodes due to no 'license' field")
        except Exception as e:
            self.logger.error("Error extracting License nodes", e)

    def __write_components(self, components: list):
        """Writes the components of the BOM to the graph

        Args:
            components (list): The components to write
            document (dict): The document to link the components to
        """
        for c in components:
            if "type" and "name" in c:
                component = {
                    "attributes": {**c},
                    "__type": self.NodeLabels.COMPONENT.value,
                    "__component_id": f"{self.NodeLabels.COMPONENT.value}_{c['type']}_{c['name']}",
                }
            else:
                self.logger.error(f"Component {c['name']} does not contain a bom-ref")
                raise AttributeError(
                    f"Component {c['name']} does not contain a bom-ref or a name and type attribute"
                )

            if "licenses" in c:
                self.__write_license(c["licenses"], component["__component_id"])
                del c["licenses"]

            if "externalReferences" in c:
                self.elements.extend(
                    [
                        {
                            "attributes": {**r},
                            "__type": self.NodeLabels.REFERENCE.value,
                            "__reference_id": f"{self.NodeLabels.REFERENCE.value}_{r['url']}",
                        }
                        for r in c["externalReferences"]
                    ]
                )
                component["references"] = []
                component["references"].extend(
                    [
                        {
                            "__toId": f"{self.NodeLabels.REFERENCE.value}_{r['url']}",
                        }
                        for r in c["externalReferences"]
                    ]
                )

            if "externalReferences" in component["attributes"]:
                del component["attributes"]["externalReferences"]

            self.__remove_attributes_key(component, "externalReferences")
            self.__remove_attributes_key(component, "licenses")
            self.__remove_attributes_key(component, "dependsOn")

            self.elements.append(component)

    def __write_dependencies(self, dependencies: list):
        """Writes the dependencies and relationships to the graph

        Args:
            dependencies (list): The dependencies to write
        """
        for d in dependencies:
            if "dependsOn" in d:
                dependency = {
                    "attributes": {**d},
                    "__type": self.NodeLabels.COMPONENT.value,
                    "__component_id": self.__get_component_id_from_bomref(d["ref"]),
                }
                dependency["dependsOn"] = []
                dependency["dependsOn"].extend(
                    [
                        {
                            "__toId": self.__get_component_id_from_bomref(dep),
                        }
                        for dep in d["dependsOn"]
                    ]
                )

                if "dependsOn" in dependency["attributes"]:
                    del dependency["attributes"]["dependsOn"]
                self.elements.append(dependency)

    def __write_vulnerabilities(self, vulnerabilities: list):
        """Writes the vulnerabilities to the graph

        Args:
            vulnerabilities (list): The vulnerabilities to write
        """
        for v in vulnerabilities:
            vul = {
                "attributes": {**v},
                "__type": self.NodeLabels.VULNERABILITY.value,
                "__vulnerability_id": f"{self.NodeLabels.VULNERABILITY.value}_{v['id']}",
            }
            if "ratings" in v and len(v["ratings"]) > 0:
                vul["attributes"]["ratings"] = v["ratings"][0]

            if "affects" in v:
                vul["affects"] = []
                vul["affects"].extend(
                    [
                        {
                            "__toId": self.__get_component_id_from_bomref(a["ref"]),
                        }
                        for a in v["affects"]
                    ]
                )
            if "affects" in vul["attributes"]:
                del vul["attributes"]["affects"]
            self.elements.append(vul)

    def __get_component_id_from_bomref(self, bomref: str) -> str:
        """Gets the correct component id for the specified bomref

        Args:
            bomref (str): The bom-ref value to find the component of

        Returns:
            str: The component id, or None
        """
        return next(
            (
                item["__component_id"]
                for item in self.elements
                if item["__type"] == self.NodeLabels.COMPONENT.value
                and "bom-ref" in item["attributes"]
                and item["attributes"]["bom-ref"] == bomref
            ),
            None,
        )

    def __remove_attributes_key(self, entity: dict, key: str):
        """Removes the specified key from the "attributes" key of the entity

        Args:
            entity (dict): The entity to remove the key from
            key (str): The key to remove from the "attributes" key of the entity
        """
        if key in entity["attributes"]:
            del entity["attributes"][key]
