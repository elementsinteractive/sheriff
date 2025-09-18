## v0.25.7 (2025-09-18)

### CI

- use lgtm-ai code reviewer action

## v0.25.6 (2025-09-17)

### Fix

- change interface of Clone
- add small suggestion by lgtm
- add security suggestion by lgtm

### Refactor

- **#52**: download repository archive instead of using git clone for GitLab

### CI

- fix lgtm reviewer workflow

### Technical

- add suggestion by lgtm

## v0.25.5 (2025-09-17)

### Fix

- increase osv timeout to accomodate bigger projects

## v0.25.4 (2025-06-23)

### CI

- add lgtm code reviewer

## v0.25.3 (2025-06-23)

### Fix

- ignore fetched projects with ignore list

## v0.25.2 (2025-06-20)

### Technical

- add dependabot

## v0.25.1 (2025-06-20)

### Fix

- **deps**: move to new gitlab dep

### Technical

- **deps**: update dependencies

## v0.25.0 (2025-06-20)

### Feat

- ignore project list

## v0.24.3 (2025-02-13)

### Fix

- close gitlab issue with iid

## v0.24.2 (2025-02-13)

### Fix

- scan directory should use slug

## v0.24.1 (2025-02-10)

### Fix

- **#48**: summary report severity count

## v0.24.0 (2025-01-13)

### Feat

- **#9**: add github project scanning support

### Technical

- change github client creation to value

## v0.23.4 (2025-01-07)

### Refactor

- **#9**: move gitlab logic to specific repository package

## v0.23.3 (2025-01-07)

### Technical

- match project config with cli config

## v0.23.2 (2024-12-30)

### Fix

- project config compatibility

## v0.23.1 (2024-12-23)

### CI

- fix ci variable indentation

## v0.23.0 (2024-12-23)

### Feat

- gitlab templates

## v0.22.2 (2024-12-23)

### CI

- fix labeler workflow

## v0.22.1 (2024-12-23)

### Refactor

- use slices.SortFunc instead of sort.Slice (#39)

## v0.22.0 (2024-12-23)

### Feat

- **#31**: Mark outdated acknowledged vulnerabilities in the issue report (#40)

## v0.21.0 (2024-12-23)

### Feat

- **#36**: post to multiple slack channels (#38)

## v0.20.1 (2024-12-18)

### Fix

- sheriff.toml config should be optional (#37)

## v0.20.0 (2024-12-18)

### Feat

- **#32**: improve configuration API
- **#32**: configure by file with internal package

### Technical

- move toml function to config package and improve comments

## v0.19.2 (2024-12-18)

### Refactor

- **#32**: move patrol and project config parsing to config package
- **#32**: move project config to separate package

## v0.19.1 (2024-12-16)

### Technical

- cleanup some old links (#33)

## v0.19.0 (2024-12-09)

### Feat

- fail-fast in case of missing scanners (#25)

## v0.18.4 (2024-12-09)

### Fix

- keep project-level config backwards-compatible

## v0.18.3 (2024-12-09)

### CI

- change goreleaser changelog and attempt a non-shallow clone (#29)

## v0.18.2 (2024-12-09)

### CI

- use goreleaser to generate binaries (#24)

## v0.18.1 (2024-12-05)

### CI

- push to dockerhub

## v0.18.0 (2024-12-05)

### Feat

- **#17**: rework cli interface

## v0.17.11 (2024-12-04)

### CI

- fix github app token use in bump action

## v0.17.10 (2024-12-04)

### CI

- use github app token

## v0.17.9 (2024-12-04)

### Fix

- change cli message on warn to "patrol" and not "scan" (#18)

## v0.17.8 (2024-12-02)

### Fix

- make `sheriff` the entrypoint of the docker image (#14)

## v0.17.7 (2024-12-02)

### Technical

- create LICENSE (#11)

## v0.17.6 (2024-12-02)

### Docs

- Add README (#10)

## v0.17.5 (2024-11-28)

### Technical

- update issue templates (#7)

## v0.17.4 (2024-11-27)

### Technical

- add CODEOWNERS

## v0.17.3 (2024-11-27)

### CI

- add releases and more tests

## v0.17.2 (2024-11-27)

### Fix

- app version 0.17.1

## v0.17.1 (2024-11-27)

### CI

- add golangci-lint

## v0.17.0 (2024-11-27)

### Feat

- warning errors to bubble up as cli exit code
- beautify GitLab report with reason and some disaclaimers
- acknowledge vulnerabilities
- report to individual slack channels
- scan groups and or projects
- config file and refactor
- adding structured logging to zerolog calls
- use context with timeout for shell commands
- fetch group projects with pagination
- testing flag to enable public channels
- improve cli with better flags and specific command
- tests for the git service
- tests for the main scan method
- coverage ignore functionality
- add slack service tests
- add gitlab service tests
- Add fix available to the vulnerability and the report
- Severity categories and some tests
- gitlab report slight from custom report
- slack message format slight improvement
- add custom report format
- support paginating slack channels
- support scanning subgroups
- add ci
- initial implementation
- initial commit

### Fix

- show only date in GL report header
- report slack project channel flag boolean
- oops, removing unnecessary file
- separate logging from messaging to the user
- removing pointer to a slice
- slack message limitations
- docker image with more functionality for gitlab
- making some stuff private
- vulnerability issue title
- fix version bump in main.go again
- version bump in main.go
- had dyslexia some with available fix, is now fixed PR this
- group vulnerabilities by categories defined directly from osvss
- incorrect warning message was missing one param
- sort vulnerabilities by CVSS score within a group casting to floats
- report is a double reference in osv.Scan
- do not close inexistant issue
- fix docker

### Refactor

- remove gitlab project pointers
- remove unnecessary pointer to report in slice
- simplify group fetching
- make vulnScanners format their own report
- change name of some packages, and merge report packages
- remove unneded `newService` private trick
- test osv scan and refactor shell stuff
- gitlab and slack service and better error handling

### Perf

- use goroutines and channels to run scan in parallel
- use goroutines for creating GitLab issues

### CI

- add version bumping with commitizen
- add workflows
- fix docker again
- add code coverage in gitlab-ci
- improve docker by not installing osv-scanner
- improve ci job definition

### Docs

- add godoc comments to all exported functions

### Technical

- add flag to enable project slack reports
- add warning when no projects to report
- add logs for sheriff configuration
- log warnings when project-config has unrecognized keys
- sheriff is patrolling
- sheriff is in town
- improve docker image
- minor improvements to ci job and sorting
- post multiple project reports
- improve logging

### Tests

- add test for gitlab issue url
- test publish to slack
- add tests for console publisher
- move to testify assertions
