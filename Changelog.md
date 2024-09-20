# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2024-09-20
## Changed
- Add `pyproject.toml`
- Add `uv.lock`
- Add/fix defaults to `Target` class `__init__`
- Add basic tests

## [1.0.1] - 2024-09-11
## Changed
- Upgrade PyYAML from 6.0 to 6.0.2
- Add `Dockerfile`
- Format python code
- Add `.pre-commit-config.yaml`

## [1.0.0] - 2021-12-16
## Breaking changes
- `prometheus_client >= 4.0` add `_total` suffix to Counter type metrics
- drop support for Python 2.7, require Python >= 3.6
## Changes
- Upgrade `jsonpath-ng`, `PyYAML` and `requests`
- Add `requirements.txt`
- Mark as `Production/stable`

## [0.2.3] - 2018-11-19
### Changed
- Require prometheus_client < 0.4.0 because of incompatible changes

## [0.2.2] - 2017-12-14
### Changed
- Use UntypedMetricFamily from upstream prometheus_client 0.1.0 library

## [0.2.1] - 2017-12-12
### Added
- Added default port and listen settings to help message

## [0.2.0] - 2017-12-08
### Added
- Added documentation to README.md

### Changed
- Rename exporter metrics

## [0.1.0] - 2017-12-08
### Added
- Initial version
