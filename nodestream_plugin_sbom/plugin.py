from nodestream.project import Project, ProjectPlugin


class SBOMPlugin(ProjectPlugin):
    def activate(self, project: Project) -> None:
        project.add_plugin_scope_from_pipeline_resources(
            name="sbom", package="nodestream_plugin_sbom"
        )
