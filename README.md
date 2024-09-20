# JSON exporter
This Prometheus exporter can be used to export metrics from a REST HTTP(S) API
that provides JSON documents. We use JSONPath (https://github.com/h2non/jsonpath-ng) to extract the metrics and
regular expressions to extract tokens from a metric path and use it to create
metric names and labels.

## Requirements
This module depends on:
 * requests
 * jsonpath_ng
 * PyYAML
 * prometheus_client

## Configuration file
The configuration file must be in YAML format. Here's an example:
```yaml
logging:
    root:
        level: INFO
        handlers:
            - console
    formatters:
        brief:
            format: "%(asctime)s %(levelname)s: %(message)s"
    handlers:
        console:
            class: logging.StreamHandler
            stream: ext://sys.stdout
            formatter: brief

targets:
    - name: logstash
      url: http://localhost:8080/logstash_node_stats.json
      headers:
          Host: www.example.com
      params:
          pretty: yes
      rules:
        - name: logstash_jvm_mem_pools_$metric
          object_path: $.jvm.mem.pools.*
          metric_path: "@.*"
          metric_type: gauge
          regex: jvm\.mem\.pools\.(?P<pool>[^.]+)\.(?P<metric>[^.]+)
          static_labels:
              pool: $pool
          dynamic_labels:
              name: $.name
        - name: logstash_jvm_mem_$metric
          object_path: $.jvm.mem.*
          metric_path: "@"
          metric_type: gauge
          regex: jvm\.mem\.(?P<metric>[^.]+)
          static_labels:
              foo: bar
          dynamic_labels:
              name: $.name
        - name: logstash_pipeline_events_$metric
          object_path: $.pipeline.events
          metric_path: "@.*"
          regex: pipeline\.events\.(?P<metric>[^.]+)
          dynamic_labels:
              name: $.name
        - name: logstash_all_$metric
          regex: (?P<metric>.*)
          dynamic_labels:
              name: $.name
        - name: logstash_test
    - name: newrelic
      url: http://localhost:8080/servers.json
      timeout: 2
      rules:
        - name: newrelic_servers_summary_$metric
          object_path: $.servers[*]
          metric_path: "@.summary.*"
          metric_type: gauge
          regex: servers\.\[(?P<id>\d+)\]\.summary\.(?P<metric>[^.]+)
          dynamic_labels:
              name: "@.name"
              host: "@.host"
          static_labels:
              id: $id
```

### Global configuration
| item | description |
|------|-------------|
| `logging` | The `logging` section changes the default logger configuration (see https://docs.python.org/2/library/logging.config.html), optional |
| `targets` | The list of targets, optional |

### Targets
| item | description |
|------|-------------|
| `name` | name of the target, used in logging and exporter metrics |
| `method` | HTTP method to use when scraping target, defaults to GET, optional |
| `url` | the target url to scrape metrics from |
| `timeout` | the timeout to use, defaults to 5 seconds, optional |
| `params` | a mapping with query parameters to add to the url, optional |
| `headers` | a mapping with HTTP headers to use when scraping target, optional |
| `body` | data to use in message body when scraping target, optional |
| `strftime` | time format string https://docs.python.org/2/library/time.html#time.strftime, can be used as template variable in `url`, `params` and `body`, optional |
| `strtime_utc` | boolean to indicate if the time used in variable must be in UTC, defaults to `yes`, optional |
| `ca_bundle` | a certificate file name or OpenSSL `c_rehash` processed directory, optional |

### Rules
| item | description |
|------|-------------|
| `name` | name of the rule, can contain variables like `$metric` or `${metric}` which are substituted with group matches from the `regex` expression. |
| `object_path` | a JSONPath expression to select the initial objects from the JSON object, optional |
| `metric_path` | a JSONPath expression to select the metrics starting from the selected `object_path`, but can be relative (using `@`) or absolute (using `$`), optional |
| `metric_type` | sets the type of the metric. Possible types are `untyped`, `gauge`, `counter`, `summary` and `histogram`. defaults to `untyped` |
| `regex` | a regular expression used to extract values ("groups") from a metric_path. These values are inserted in template varaibles into rule names or static labels, optional |
| `dynamic_labels` | key-value pairs that are added to a metric. The value of this label is determined dynamically with a JSONPath expression and must yield a single string value, optional |
| `static_labels` | key-value pairs that are added to a metric. The value of this label is determined by inserting template values (variables must start with a `$` or be enclosed with `${` and `}`). For example using variables like `$metric` or `${metric}`, optional |

## Test with docker
Steps to create a test setup and test with docker:
1. create a test configuration file `test.yaml` like:
```yaml
logging:
    root:
        level: INFO
        handlers:
            - console
    formatters:
        brief:
            format: "%(asctime)s %(levelname)s: %(message)s"
    handlers:
        console:
            class: logging.StreamHandler
            stream: ext://sys.stdout
            formatter: brief

targets: []
```
1. build the container image with `docker build -t json_exporter .`
1. run the container with
```bash
docker run -it --rm -p 8000:8000  -v `pwd`:/workspace json_exporter /workspace/test.yaml
```
1. in a separate window check if you get metrics:
```bash
curl -sv localhost:8000
```
## Development
Setup python:
```bash
uv python install 3.8
uv python pin 3.8
```
Setup virtualenv:
```bash
uv sync
```
Run tests:
```bash
uv run pytest
```
### Before release
* update `__version__` in `json_exporter/__init__.py`
* update `Changelog.md`
* run:
```bash
uv export --no-dev  --frozen --no-hashes > requirements.txt
```
* test package build:
```bash
uv build
```
### Release
After new version has been merged into master:
* create Github release
