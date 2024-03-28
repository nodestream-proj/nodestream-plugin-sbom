import logging
from nodestream.pipeline import Extractor
from nodestream_plugin_sbom.utils.spdx_writer import SPDXWriter
import flatdict
import requests


class GithubSBOMExtractor(Extractor):
    bearer_token: str = None

    def __init__(self, repos: list[str], bearer_token: str = None) -> None:
        if repos is None:
            raise AttributeError(
                "When using the GithubSBOMExtractor 'repos' is required and cannot be empty"
            )
        self.repos = repos
        if bearer_token is not None:
            self.bearer_token = bearer_token
        self.logger = logging.getLogger(self.__class__.__name__)

    def fetch_sbom_from_github(self, repo: str) -> object:
        headers = {
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept": "application/vnd.github+json",
        }
        if self.bearer_token is not None:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{repo}/dependency-graph/sbom",
                headers=headers,
            )

            if resp.ok:
                data = resp.json()
                return data["sbom"]
            else:
                raise Exception(
                    f"Failed to fetch SBOM from GitHub for repo {repo}: {resp.text}"
                )
        except Exception as e:
            self.logger.error(f"Failed to fetch SBOM from GitHub for repo {repo}: {e}")
            raise Exception(f"Failed to fetch SBOM from GitHub for repo {repo}")

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
        for repo in self.repos:
            record = self.fetch_sbom_from_github(repo)
            writer = SPDXWriter(record)
            elements = writer.write_document()
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
