from json_exporter import main
from prometheus_client.metrics_core import Metric


def test_empty_config():
    collector = main.JSONCollector({})
    assert list(collector.collect()) == []


class MockTarget(main.Target):
    def scrape(self):
        self.metric_families = []
        for rule in self.rules:
            for family in rule.get_metric_families(self.data):
                self.metric_families.append(family)


def test_simple_rule():
    collector = main.JSONCollector({})
    target = MockTarget("test_target")
    target.data = {"metric1": 1}
    rule_config = {"name": "test_rule"}
    rule = collector.read_rule_config(rule_config, target.name, 0)
    target.add_rule(rule)
    collector.targets = [target]
    results = list(collector.collect())
    assert isinstance(results[0], Metric)
