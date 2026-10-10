# Beyond GitHub Integrations

PLEx is CLI-first and works in any CI/CD system. Use standard outputs
(`--json`, `--sarif`, `--html`, `--md`, `--snippets`) and archive them as
artifacts.

## GitLab CI

```yaml
stages: [analyze]

plex:
  stage: analyze
  image: python:3.12
  script:
    - pip install git+https://github.com/KOKUTBON/PLEx.git
    - plex analyze . --changed-only --compare-base \
        --base-ref origin/main \
        --json out/plex.json \
        --md out/plex.md \
        --sarif out/plex.sarif \
        --snippets out/plex.snippets.md
  artifacts:
    when: always
    paths:
      - out/plex.json
      - out/plex.md
      - out/plex.sarif
      - out/plex.snippets.md
```

If your CI provides a merge-request base branch variable, pass it to
`--base-ref` for accurate diffs.

## Jenkins (Declarative Pipeline)

```groovy
pipeline {
  agent any
  stages {
    stage('PLEx') {
      steps {
        sh 'pip install git+https://github.com/KOKUTBON/PLEx.git'
        sh '''
          plex analyze . --changed-only --compare-base \
            --base-ref origin/main \
            --json out/plex.json \
            --md out/plex.md \
            --sarif out/plex.sarif \
            --snippets out/plex.snippets.md
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'out/*', fingerprint: true
        }
      }
    }
  }
}
```

## Azure DevOps Pipelines

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: |
      pip install git+https://github.com/KOKUTBON/PLEx.git
      plex analyze . --changed-only --compare-base \
        --base-ref origin/main \
        --json out/plex.json \
        --md out/plex.md \
        --sarif out/plex.sarif \
        --snippets out/plex.snippets.md
    displayName: 'Run PLEx'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: 'out'
      ArtifactName: 'plex'
```

## Baseline caching outside GitHub

If you cannot rely on git history in CI, store a baseline JSON artifact on
main and reuse it in PRs:

```bash
# on main
plex baseline . --json out/plex.json

# on PR
plex analyze . --baseline-json out/plex.json --compare-base
```

## Notes

- SARIF can be ingested by many security/reporting tools; otherwise, archive it.
- JSON is best for dashboards and custom automation.
- Markdown/HTML are best for human review.
