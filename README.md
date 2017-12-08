JSON exporter
=============

This Prometheus exporter can be used to export metrics from a REST HTTP(S) API
that provides JSON documents. We use JSONPath to extract the metrics and
regular expressions to extract tokens from a metric path and use it to create
metric names and labels.

Requirements
------------

This module depends on:
 * requests
 * jsonpath_ng
 * PyYAML
 * prometheus_client

Configuration file
------------------

The configuration file must be in YAML format. Here's an example:
```
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
The `logging` section is optional and can be omitted.

Targets must have a `name` and `url`. `rules` can be omitted as well,
but that doesn't make much sense. You can override the default timeout
(5 seconds) by specifying a new `timeout` for a target.
You can add a `ca_bundle` configuration item to a target which points
to a certificate file or OpenSSL c_rehash processed directory (see
http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification)

Rules must have a `name` and can contain variables like `$metric` or
`${metric}` which are substituted with group matches from the `regex`
expression.
The `object_path` is a JSONPath expression to select the initial objects
from the JSON object.
The `metric_path` is a JSONPath expression to select the
metrics starting from the selected `object_path`, but can be relative (using
`@) or absolute (using `$`).
`metric_type` sets the type of the metric and defaults to `untyped`. Possibly
types are `untyped, `gauge`, `counter`, `summary` and `histogram`.
`regex` is a regular expression used to extract values ("groups") from a
metric_path. These values are inserted in template values into rule names or
static labels.
`dynamic_labels` are key-value pairs that are added to a metric. The value of
this label is determined dynamically with a JSONPath expression and must
yield a single string value.
`static_labels` are key-value pairs that are added to a metric. The value of
this label is determined by inserting template values (variables must start
with a `$` or be enclosed with `${` and `}`). For example using variables
like `$metric` or `${metric}`.
