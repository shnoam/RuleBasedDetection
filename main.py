import pandas as pd
from rules import Rule, MultipleRequests
import json

def read_file(path):
    if path.endswith('.json'):
        with open(path, 'r') as file:
            file = json.load(file)
    elif path.endswith('.csv'):
        with open(path, 'r') as file:
            file = pd.read_csv(path)
    return file
def create_rules(rules):
    rules_objects = []

    for rule_dict in rules:
        classification = rule_dict.pop('classification', None)
        rule_id = rule_dict.pop('rule_id')
        operator = rule_dict.pop('operator', None)
        if rule_dict.get('type') == "MultipleRequests":
            num_of_times = rule_dict.pop('num_of_times')
            time_interval = rule_dict.pop('time_interval')
            rule = MultipleRequests(rule_id, num_of_times, time_interval)
        else: # basic rule
            rule = Rule(rule_id, rule_dict,classification,operator)
        rules_objects.append(rule)
    return rules_objects

def process_log(log, rules):
    suspicious_logs = []
    for log_entry in log:
        for rule in rules:
            if isinstance(rule, Rule):
                classification = rule.apply(log_entry)
                if classification == 1: # suspicious
                    suspicious_logs.append({
                        "log_entry": log_entry,
                        "detected_by": rule.rule_id
                    })
    for rule in rules:
        if isinstance(rule, MultipleRequests):
            suspicious_entries = rule.apply(log)
            for entry in suspicious_entries:
                suspicious_logs.append({
                    "log_entry": entry,
                    "detected_by": rule.rule_id
                })
    return suspicious_logs

def main():
    log_path = 'logs.json'
    rules_requiremnts_path = 'rules_requirements.json'
    log = read_file(path=log_path)
    rules_requiremnts = read_file(path=rules_requiremnts_path)
    rules = create_rules(rules_requiremnts)
    suspicious_logs = process_log(log, rules)
    return suspicious_logs

if __name__ == "__main__":
    print(main())

