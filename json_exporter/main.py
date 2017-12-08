#!/usr/bin/python
'''
Generic JSON HTTP(S) API exporter.
Based on
https://www.robustperception.io/writing-json-exporters-in-python/
https://www.robustperception.io/writing-a-jenkins-exporter-in-python/
'''
import sys
import time
import argparse
import logging
import logging.config
import re
import threading
import signal
from string import Template
import requests
from prometheus_client import start_http_server, Histogram, Counter
from prometheus_client.core import Metric, GaugeMetricFamily, CounterMetricFamily, SummaryMetricFamily, HistogramMetricFamily, REGISTRY
import yaml
from yaml.error import YAMLError
import jsonpath_ng.ext

VERSION = '0.2.0'
NAN = float('NaN')
INVALID_METRIC_RE = re.compile(r'[^0-9a-zA-Z_:]')
MULTI_UNDERSCORE_RE = re.compile(r'_+')
TIMEOUT = 5
PORT = 8000
THREAD_JOIN_TIMEOUT = 1
DEFAULT_LOG_CONFIG = """
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
"""

# Create a metric to track time spent and requests made.
REQUEST_TIME = Histogram('json_exporter_collector_duration_seconds', 'Time spent collecting metrics from a target', ['name'])
ERROR_COUNTER = Counter('json_exporter_collector_error_count', 'Number of collector errors for a target', ['name'])

def debug(msg, *args):
    logging.debug(msg, *args)

def info(msg, *args):
    logging.info(msg, *args)

def warn(msg, *args):
    logging.warn(msg, *args)

def error(msg, *args, **kwargs):
    if kwargs.get('target'):
        ERROR_COUNTER.labels(kwargs.get('target')).inc()
    else:
        ERROR_COUNTER.inc()
    logging.error(msg, *args)

def fail(msg):
    'Print message and exit.'
    print >> sys.stderr, msg
    sys.exit(1)

class UntypedMetricFamily(Metric):
    '''A single untyped metric and its samples.
    For use by custom collectors.
    '''
    def __init__(self, name, documentation, value=None, labels=None):
        Metric.__init__(self, name, documentation, 'untyped')
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value)

    def add_metric(self, labels, value):
        '''Add a metric to the metric family.
        Args:
        labels: A list of label values
        value: The value of the metric.
        '''
        self.samples.append((self.name, dict(zip(self._labelnames, labels)), value))

def configure_logger(args, config):
    'Create logging'
    log_config = {'version': 1}
    if 'logging' in config:
        log_config.update(config['logging'])
    else:
        log_config.update(yaml.safe_load(DEFAULT_LOG_CONFIG))

    logging.config.dictConfig(log_config)
    logger = logging.getLogger()
    if args.quiet:
        logger.setLevel(logging.WARNING)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

def parse_args():
    'Parse program arguments'
    parser = argparse.ArgumentParser(
        description='export metrics from JSON HTTP(S) API endpoints (v{})'.format(VERSION))
    parser.add_argument("config", help='configuration file')
    parser.add_argument('-p', '--port', help='port to listen on',
                        type=int, default=PORT)
    parser.add_argument('-l', '--listen', help='address to listen on',
                        default="0.0.0.0")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="store_true")
    group.add_argument("-q", "--quiet", action="store_true")
    return parser.parse_args()

def load_config(filename):
    'Load YAML config from filename.'
    try:
        with open(filename) as config_file:
            config = yaml.load(config_file)
    except (OSError, IOError) as exc:
        fail('could not open config file {} ({})'.format(filename, exc))
    except YAMLError as exc:
        fail('parse error in YAML configuration file {}:\n{}'.format(filename, exc))

    if not isinstance(config, dict):
        fail('invalid YAML configuration in file {}'.format(filename))

    return config

class Rule(object):
    'Represent a single rule to collect metrics from a scraped JSON object.'
    def __init__(self, target_name, name, family, object_path, object_parser, metric_path, metric_parser,
                 static_label_keys, static_label_values, label_parsers, regex):
        self.target_name = target_name
        self.name = name
        self.family = family
        self.object_path = object_path
        self.object_parser = object_parser
        self.metric_path = metric_path
        self.metric_parser = metric_parser
        self.static_label_keys = static_label_keys
        self.static_label_values = static_label_values
        self.label_parsers = label_parsers
        self.regex = regex

    def __str__(self):
        return 'name=%s target=%s object_path=%s metric_path=%s static_label_keys=%r static_label_values=%r dynamic_labels=%r regex=%s' % (
            self.name,
            self.target_name,
            self.object_path,
            self.metric_path,
            self.static_label_keys,
            self.static_label_values,
            self.label_parsers.keys(),
            self.regex.pattern)

    def render(self, tmpl, variables):
        'Render template tmpl with variables.'
        return Template(tmpl).safe_substitute(variables)

    def match_regex(self, path):
        'Return dictionary with regular expression groups from match on path.'
        m = self.regex.match(path)
        if m is not None:
            return m.groupdict()
        return {}

    def get_metric_name(self, name):
        'Convert name into valid metric name.'
        return MULTI_UNDERSCORE_RE.sub('_', INVALID_METRIC_RE.sub('_', name))

    def get_metrics(self, data):
        'Return metric matches and values from dictionary data.'
        for match in self.metric_parser.find(data):
            try:
                if match.value is None:
                    value = NAN
                else:
                    value = float(str(match.value))
            except ValueError:
                debug('target %s, rule %s, skipping value %s for path %s (not a number)',
                              self.target_name, self.name, match.value, match.full_path)
                continue
            yield (match, value)

    def get_dynamic_labels(self, obj):
        'Find all dynamic labels from jsonpath match obj.'
        if not self.label_parsers:
            return [], []
        dynamic_labels = {}
        for label in self.label_parsers:
            res = [match.value for match in self.label_parsers[label].find(obj)]
            if len(res) != 1:
                warn('target %s, rule %s, dynamic label "%s" returned %d matches instead of 1 for object path %s', 
                             self.target_name, self.name, label, len(res), obj.full_path)
                dynamic_labels[label] = ""
            elif not isinstance(res[0], basestring):
                warn('target %s, rule %s, dynamic label "%s" returned non-string value %r for object path %s',
                             self.target_name, self.name, label, res[0], obj.full_path)
                dynamic_labels[label] = ""
            else:
                dynamic_labels[label] = res[0]
        dynamic_label_keys = sorted(dynamic_labels)
        dynamic_label_values = [dynamic_labels[label] for label in dynamic_label_keys]

        return dynamic_label_keys, dynamic_label_values

    def get_metric_families(self, data):
        'Return all Prometheus metric families extracted from dictionary data.'
        for obj in self.object_parser.find(data):
            cache = {}
            dynamic_label_keys, dynamic_label_values = self.get_dynamic_labels(obj)
            labels = tuple(self.static_label_keys + dynamic_label_keys)

            for match, value in self.get_metrics(obj):
                metric_path = str(match.full_path)
                re_variables = self.match_regex(metric_path)
                metric_name = self.get_metric_name(self.render(self.name, re_variables))
                metric_help = 'from %s' % metric_path
                key = tuple((metric_name, labels))
                if key not in cache:
                    cache[key] = self.family(metric_name, metric_help, labels=labels)

                label_values = [self.render(label, re_variables) for label in self.static_label_values] + dynamic_label_values
                cache[key].add_metric(label_values, value)

            for metric_name in cache:
                yield cache[metric_name]

class Target(object):
    'Represent a single target HTTP(S) endpoint to scrape JSON from.'
    def __init__(self, name, url, params, headers, timeout, ca_bundle):
        self.name = name
        self.url = url
        self.params = self._str_params(params)
        self.headers = headers
        self.timeout = timeout
        self.session = requests.Session()
        # verify can also be set to ca_bundle file or directory
        # see http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        self.session.verify = ca_bundle
        self.rules = []
        self.metric_families = []

    def __str__(self):
        return 'name=%s url=%s params=%r headers=%r timeout=%r' % (self.name,
                                                                   self.url,
                                                                   self.params,
                                                                   self.headers,
                                                                   self.timeout)

    def add_rule(self, rule):
        'Add a Rule object.'
        self.rules.append(rule)

    def run(self):
        'Scrape this target.'
        with REQUEST_TIME.labels(self.name).time():
            self.scrape()

    def get_metric_families(self):
        'Return collected metric families.'
        for family in self.metric_families:
            yield family

    def error(self, msg):
        'format error message with target name and url.'
        error('target {} at url {} {}'.format(self.name, self.url, msg), target=self.name)

    def scrape(self):
        'Scrape the target and store metric families'
        try:
            response = self.session.get(self.url, params=self.params,
                                        headers=self.headers,
                                        timeout=self.timeout)
            response.raise_for_status()

            try:
                data = response.json()
            except ValueError:
                self.error('could not decode JSON response')
                return

            self.metric_families = []
            for rule in self.rules:
                for family in rule.get_metric_families(data):
                    self.metric_families.append(family)
        except requests.HTTPError as exc:
            self.error('received unsuccesful response ({})'.format(exc))
        except requests.ConnectionError as exc:
            self.error('could not connect to url ({})'.format(exc))
        except requests.Timeout as exc:
            self.error('connection timed out')
        except requests.TooManyRedirects as exc:
            self.error('too many redirects')
        except requests.RequestException as exc:
            self.error('error in request ({})'.format(exc))

    def _str_params(self, params):
        'Stringify elements in param dict.'
        d = {}
        for k in params:
            if params[k] is None:
                d[k] = ""
            elif isinstance(params[k], list):
                d[k] = [str(i) for i in params[k]]
            else:
                d[k] = str(params[k])
        return d

def read_from(source, item, default=None):
    'Try to get item from source and return default if result is false.'
    return source.get(item) or default

class JSONCollector(object):
    'Single JSON endpoint metric collector'
    def __init__(self, config):
        self.targets = list(self.read_config(config))

    def read_target_config(self, target, glb_timeout, glb_ca_bundle, target_idx):
        'Read configuration items from target config.'
        target_name = read_from(target, 'name')
        url = read_from(target, 'url')
        params = read_from(target, 'params', {})
        headers = read_from(target, 'headers', {})
        timeout = read_from(target, 'timeout', glb_timeout)
        ca_bundle = read_from(target, 'ca_bundle', glb_ca_bundle)
        if not target_name:
            warn('skipping target %d without a name', target_idx + 1)
            return None
        if not url:
            warn('skipping target %s without a url', target_name)
            return None
        return Target(target_name, url, params, headers, timeout, ca_bundle)

    def read_rule_config(self, rule, target_name, rule_idx):
        'Read configuration items from rule config.'
        rule_name = rule.get('name')
        metric_type = rule.get('metric_type', 'untyped')
        object_path = read_from(rule, 'object_path', '$')
        metric_path = read_from(rule, 'metric_path', '@..*')
        static_labels = read_from(rule, 'static_labels', {})
        dynamic_labels = read_from(rule, 'dynamic_labels', {})
        regex = read_from(rule, 'regex', r'^$')

        if not rule_name:
            warn('skipping target %s, rule %d without a name',
                         target_name, rule_idx + 1)
            return None

        try:
            object_parser = jsonpath_ng.ext.parse(object_path)
        except Exception as exc:
            warn('skipping target %s, rule %s with invalid object_path %s (%s)',
                         target_name, rule_name, object_path, exc)
            return None
        
        family = {'untyped':   UntypedMetricFamily,
                  'counter':   CounterMetricFamily,
                  'gauge':     GaugeMetricFamily,
                  'summary':   SummaryMetricFamily,
                  'histogram': HistogramMetricFamily
                 }.get(metric_type)
        if family is None:
            warn('skipping target %s, rule %s with invalid metric_type (%s)',
                         target_name, rule_name, metric_type)
            return None
        
        try:
            metric_parser = jsonpath_ng.ext.parse(metric_path)
        except Exception as exc:
            warn('skipping target %s, rule %s with invalid metric_path %s (%s)',
                         target_name, rule_name, metric_path, exc)
            return None

        static_label_keys = sorted(static_labels)
        static_label_values = [static_labels[label] for label in static_label_keys]
        label_parsers = {}
        for label in sorted(dynamic_labels):
            label_value = dynamic_labels[label]
            try:
                label_parsers[label] = jsonpath_ng.ext.parse(label_value)
            except Exception as exc:
                warn('skipping target %s, rule %s with invalid dynamic label %s=%s (%s)', 
                             target_name, rule_name, label, label_value, exc)
                return None
        
        try:
            regex = re.compile(read_from(rule, 'regex', r'^$'))
        except Exception as exc:
            warn('skipping target %s, rule %s with invalid regex (%s)',
                         target_name, rule_name, exc)
            return None

        return Rule(target_name, rule_name, family,
                    object_path, object_parser, metric_path,
                    metric_parser, static_label_keys,
                    static_label_values, label_parsers, regex)

    def read_config(self, config):
        'Read configuration items from config.'
        glb_timeout = read_from(config, 'timeout', TIMEOUT)
        glb_ca_bundle = read_from(config, 'ca_bundle', True)
        for target_idx, target in enumerate(read_from(config, 'targets', [])):
            target_obj = self.read_target_config(target, glb_timeout, glb_ca_bundle, target_idx)
            if target_obj is None:
                continue
            info('configured target %s', target_obj)

            for rule_idx, rule in enumerate(read_from(target, 'rules', [])):
                rule = self.read_rule_config(rule, target_obj.name, rule_idx)
                if rule is None:
                    continue
                target_obj.add_rule(rule)

                info('configured rule %s', rule)

            yield target_obj

    def collect(self):
        'Collect Prometheus metric families from endpoints.'
        threads = []
        for target in self.targets:
            thread = threading.Thread(target=target.run, name=target.name)
            thread.start()
            threads.append(thread)

        done = False
        while not done:
            done = True
            for thread in threads:
                thread.join(THREAD_JOIN_TIMEOUT)
                if thread.is_alive():
                    done = False

        for target in self.targets:
            for metric_family in target.get_metric_families():
                yield metric_family

class Notifier(object):
    'Get notified about signals.'
    def __init__(self):
        self.terminate = False
        signal.signal(signal.SIGINT,  self.handler)
        signal.signal(signal.SIGTERM, self.handler)
        signal.signal(signal.SIGHUP,  self.handler)

    def handler(self, signum, frame):
        'Handler for signals.'
        if signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.terminate = True

def main():
    'Main'
    args = parse_args()
    config = load_config(args.config)
    configure_logger(args, config)
    info('starting json_exporter v{}'.format(VERSION))
    info("loaded config")
    debug("config:\n%r", config)

    notifier = Notifier()
    REGISTRY.register(JSONCollector(config))

    info('starting http server on {}:{}'.format(args.listen, args.port))
    start_http_server(args.port, args.listen)
    while not notifier.terminate:
        time.sleep(1)
    info('stopping http server on {}:{}'.format(args.listen, args.port))

if __name__ == '__main__':
    main()
