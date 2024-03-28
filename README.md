# Nodestream Software Bill of Material (SBOM) Plugin

This repo contains a Nodestream plugin to import SBOM files in JSON formatted [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) into an opinionated graph data model in a graph database. Nodestream is a developer friendly Python framework for materializing and working with graph databases.

## Features

- An opinionanted graph data model for SBOM data analysis
- Support for JSON formatted [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) data files
- Automated download of SBOM files from Github and import them into a graph
- Automated export of SBOM files from [Amazon Inspector](https://aws.amazon.com/inspector/) and import them into a graph

## Getting Started

For information on configuring and using Nodestream please visit the [Documentation](https://nodestream-proj.github.io/nodestream) on Github Pages.

To use the Nodestream SBOM plugin you first must install it using PyPi.

```bash
  pip install nodestream-plugin-sbom
```

## Running Pipelines

The SBOM plugin comes with three pre-configured pipelines:

- `sbom` - This will import SBOM files from a local directory
- `sbom_github` - This will export SBOM files from the provided Github repo and import them into a graph database
- `sbom_amazon_inspector` - This will export SBOM files using [Amazon Inspector](https://aws.amazon.com/inspector/) and import them into a graph database

Once installed you will need to add some configuration depending on which pipeline you want to run:

### Local SBOM files

`nodestream.yaml` configuration

```
plugins:
- name: sbom
  config:
    paths: <The local directory or file with SBOM files to import>

targets:
  my-db:
    database: neptune
    graph_id: <YOUR GRAPH ID>
    mode: analytics
```

To run the pipeline:

```
nodestream run sbom --target my-db -v
```

### Github Repositories

`nodestream.yaml` configuration

```
plugins:
- name: sbom
  config:
    repos: [A list of owner/repos to import e.g. nodestream-proj/nodestream]

targets:
  my-db:
    database: neptune
    graph_id: <YOUR GRAPH ID>
    mode: analytics
```

To run the pipeline:

```
nodestream run sbom_github --target my-db -v
```

### Using it with Amazon Inspector

To use this the Amazon Inspector pipeline you must provide

`nodestream.yaml` configuration

```
plugins:
- name: sbom
  config:
    bucketName: <S3 Bucket Name>
    keyPrefix: <S3 Bucket Key Prefix>
    kmsKeyArn: <KMS Key ARN>

targets:
  my-db:
    database: neptune
    graph_id: <YOUR GRAPH ID>
    mode: analytics
```

To run the pipeline:

```
nodestream run sbom --target my-db -v
```

For configuration of the S3 bucket and KMS key required for Amazon Inspector please refer to the documentation:
https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html

## Documentation

A software bill of materials (SBOM) is a critical component of software development and management, helping organizations to improve the transparency, security, and reliability of their software applications. An SBOM acts as an "ingredient list" of libraries and components of an software application that:

- Enables software creators to track dependencies within their applications
- Provides security personnel the ability to examine and risk potential vulnerabilities within an environment
- Provide legal personnel the information needed to assure that a particular software is in compliance with all licensing requirements.

When combined together, the functionality provided by SBOMs is a critical piece of

A software bill of materials (SBOM) is a comprehensive list of the components, libraries, and dependencies used in a software application or system. It provides a detailed breakdown of the software's architecture, including the names, versions, licenses, and optionally the vulnerabilities of each component.

An SBOM provides those who create, purchase, and operate software with insight and understanding of the supply chain enabling them to track known and newly emerged vulnerabilities and risks. SBOM and SBOM analysis are part of the foundational data layer on which further security
tools, practices, and procedures should be built. SBOMs can be generated using a variety of tools and technologies, including open-source tools, automated tools, and manual processes. They can be formatted in different formats, such as JSON, YAML, or XML, to suit different needs and use cases. There are currently two main open-source and machine-readable formats for SBOMs:

- [CycloneDX](https://cyclonedx.org/) - developed by the Open Web Application Security Project (OWASP) this is a format that is focused on providing simple automation to ease adoption. In addition to the minimum requirements for data in an SBOM, CycloneDX files can also contain information about associated vulnerabilities within the system or application.

- [SPDX](https://spdx.dev/) - Developed by the Linux Foundation this format was originally created to facilitate the exchange of software metadata, with a particular focus on licensing information. Since it's creation in 2011 this has evolved to include additional data fields that enables its use as an SBOM format.

### Graph Data Model

The key elements of this data model are:

![SBOM Schema](./img/SBOM%20Schema.png "SBOM Schema")

**Node Types**

- `Document` - This represents the SBOM document as well as the metadata associated with that SBOM. In a CycloneDX file, this is sourced from the [`metadata`](https://cyclonedx.org/guides/sbom/object-model/#metadata) element of the SBOM. In an SPDX file, this is sourced from the ['document'](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/) element of the SBOM.
- `Component` - This represents a specific component of a software system. In a CycloneDX file, this is sourced from the [`externalReferences`](https://cyclonedx.org/guides/sbom/object-model/#components) elements of the SBOM `component`. In an SPDX file, this is sourced from the ['packages'](https://spdx.github.io/spdx-spec/v2.3/package-information/) elements of the SBOM.
- `Reference` - This represents a reference to any external system which the system wanted to include as a reference. This can range from package managers, URLs to external websites, etc. In a CycloneDX file, this is sourced from the [`components`](https://cyclonedx.org/guides/sbom/object-model/#components) elements of the SBOM. In an SPDX file, this is sourced from the ['externalRef'](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field) elements of the SBOM `packages`.
- `Vulnerability` - This represents a specific known vulnerability for a component. This is only available with CycloneDX files and is sourced from the [`vulnerabilities`](https://cyclonedx.org/guides/sbom/object-model/#vulnerabilities) elements of the SBOM.

**Edge Types**

- `DESCRIBES`/`DEPENDS_ON`/`DEPENDENCY_OF`/`DESCRIBED_BY`/`CONTAINS` - This represents the type of relationship between a `Document` and a `Component` in the system. For CycloneDX files only the `DEPENDS_ON` field is used. For SPDX files the appropriate edge type is determined by the relationship type specified in the [`relationship`](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) elements.
- `REFERS_TO` - This represents a reference between a `Component` and a `Reference`
- `AFFECTS` - This represents that a particular `Component` is affected by the connected `Vulnerability`

## Issues and Feature Requests

Please file all issues and feature requests using Github issues on this repo. We will address them as soon as reasonable.

## Authors

- Dave Bechberger ([@bechbd](https://www.github.com/bechbd))
