import uuid
from typing import Any
from .sbom_writer import SBOMWriter


class SPDXWriter(SBOMWriter):
    def write_document(self):
        """ "This writes the SPDX document

        Args:
            bom (dict): The dict of the BOM

        Returns:
            bool: True if successful, False if not
        """
        try:
            self.logger.info("Writing bom metadata")

            self.__write_bom(self.bom)

            if "packages" in self.bom:
                self.logger.info("Writing packages as components")
                self.__write_packages(self.bom["packages"])

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
        document_id = f"{self.NodeLabels.DOCUMENT.value}_{uuid.uuid4()}"
        document = {
            "attributes": {**bom, **bom["creationInfo"]},
            "__type": self.NodeLabels.DOCUMENT.value,
            "__document_id": document_id,
        }
        # Remove the creationInfo as it is promoted to top level attributes
        self.__remove_attributes_key(document, "creationInfo")

        # Do mappings from Cyclone DX to more generic name
        document["attributes"]["specVersion"] = document["attributes"].pop(
            "spdxVersion"
        )
        document["attributes"]["createdTimestamp"] = document["attributes"].pop(
            "created"
        )
        document["attributes"]["bomFormat"] = "SPDX"

        if "relationships" in document["attributes"]:
            document = self.__write_relationships(self.bom["relationships"], document)
            self.__remove_attributes_key(document, "relationships")

        self.elements.append(document)

    def __write_licenses(self, licenses: Any, toId: str):
        """Writes the license of the BOM to the graph

        Args:
            license (Any): The licenses to write
            toId (str): The id of the node to connect to
        """
        # Adding a ternary operation here to ensure that licenses is a list since it can have a cardinality of 0..N
        licenses = [licenses] if isinstance(licenses, str) else licenses
        for license in licenses:
            license = {
                "attributes": {"name": license},
                "__type": self.NodeLabels.LICENSE.value,
                "__license_id": f"{self.NodeLabels.LICENSE.value}_{license.lower()}",
            }
            license["licensed_by"] = [
                {
                    "__toId": toId,
                }
            ]
            self.elements.append(license)

    def __write_packages(self, packages: list):
        """Writes the packages of the BOM to the graph

        Args:
            packages (list): The packages to write
        """

        for c in packages:
            component = {
                "attributes": {**c},
                "__type": self.NodeLabels.COMPONENT.value,
                "__component_id": f"{self.NodeLabels.COMPONENT.value}_{c['SPDXID']}",
            }

            # Pull out the external references into there own nodes
            if "externalRefs" in component["attributes"]:
                component["references"] = []
                for r in component["attributes"]["externalRefs"]:
                    self.elements.append(
                        {
                            "attributes": {**r},
                            "__type": self.NodeLabels.REFERENCE.value,
                            "__reference_id": f"{self.NodeLabels.REFERENCE.value}_{r['referenceLocator']}",
                        }
                    )
                    component["references"].extend(
                        [
                            {
                                "__toId": f"{self.NodeLabels.REFERENCE.value}_{r['referenceLocator']}",
                            }
                            for r in component["attributes"]["externalRefs"]
                        ]
                    )
                    # If the reference type is the purl, and one does not exist at the component level then promote it
                    if r["referenceType"] == "purl" and "purl" not in component:
                        component["attributes"]["purl"] = r["referenceLocator"]
                self.__remove_attributes_key(component, "externalRefs")

            # Pull out the license fields into there own nodes
            if "licenseDeclared" in component["attributes"]:
                self.__write_licenses(
                    [component["attributes"]["licenseDeclared"]],
                    component["__component_id"],
                )
                self.__remove_attributes_key(component, "licenseDeclared")
            if "licenseConcluded" in component["attributes"]:
                self.__write_licenses(
                    [component["attributes"]["licenseConcluded"]],
                    component["__component_id"],
                )
                self.__remove_attributes_key(component, "licenseConcluded")
            if "licenseInfoFromFiles" in component["attributes"]:
                self.__write_licenses(
                    [component["attributes"]["licenseInfoFromFiles"]],
                    component["__component_id"],
                )
                self.__remove_attributes_key(component, "licenseInfoFromFiles")

            self.elements.append(component)

    def __write_relationships(self, relationships: list, document: object):
        """Writes the relationships of the BOM to the graph

        Args:
            relationships (list): The relationships to write
            document_id (str): The document id to link the relationships to
        """
        self.logger.info("Writing relationship edges")
        document["describes"] = []
        document["depends_on"] = []
        document["dependency_of"] = []
        document["described_by"] = []
        document["contains"] = []

        # Connect the packages and the references to the documentDescribes to the Document
        document["describes"].extend(
            [
                {
                    "__toId": f"{self.NodeLabels.COMPONENT.value}_{r['SPDXID']}",
                }
                for r in document["attributes"]["packages"]
            ]
        )
        self.__remove_attributes_key(document, "packages")
        # Add primary component link to the document
        if "documentDescribes" in document["attributes"]:
            document["describes"].extend(
                [
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d}",
                    }
                    for d in document["attributes"]["documentDescribes"]
                ]
            )

        for d in relationships:
            if d["relationshipType"] == "DESCRIBES":
                document["describes"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}",
                    }
                )
            elif d["relationshipType"] == "DEPENDS_ON":
                document["depends_on"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            elif d["relationshipType"] == "DEPENDENCY_OF":
                document["dependency_of"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            elif d["relationshipType"] == "DESCRIBED_BY":
                document["described_by"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            elif d["relationshipType"] == "CONTAINS":
                document["contains"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            else:
                self.logger.warning(
                    f"Unknown relationship type {d['relationshipType']}"
                )

        return document

    def __remove_attributes_key(self, entity: dict, key: str):
        """Removes the specified key from the "attributes" key of the entity

        Args:
            entity (dict): The entity to remove the key from
            key (str): The key to remove from the "attributes" key of the entity
        """
        if key in entity["attributes"]:
            del entity["attributes"][key]
