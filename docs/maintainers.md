# Maintainer notes

## Releases

release-please keeps a release pull request open on `main`. Merging it tags `agent-vX.Y.Z` and, if the chart changed, `chart-vX.Y.Z`. The `Release` workflow then:

- scans the image with Trivy and stops on a critical finding that has a fix;
- pushes the image for `amd64` and `arm64` to `ghcr.io/statustick/agent` with an SBOM and provenance, and signs it with cosign;
- attaches the static binaries and `SHA256SUMS` to the GitHub release;
- pushes the chart to `oci://ghcr.io/statustick/charts`.

Release pull requests get no CI run, so merge them with the admin bypass. If the image step fails after the release was created, run the `Release` workflow by hand with the version to publish the image again.

The repository variables `AGENT_IMAGE` and `CHART_REGISTRY` change where the image and the chart go.
