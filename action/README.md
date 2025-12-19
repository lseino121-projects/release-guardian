# Release Guardian (GitHub Action)

Release Guardian implements **Release Decision Intelligence (RDI)**: it runs security scanners and produces **one clear, explainable verdict per PR**.

> v1 is under active development. Current version is a scaffold that posts a placeholder verdict.

## Usage

```yaml
name: Release Guardian

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  statuses: write

jobs:
  rdi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Release Guardian
        uses: lseino121-projects/release-guardian@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
