from abc import ABC, abstractmethod
from datetime import datetime

class Rule:
    def __init__(self,rule_id,condition_requirements,classification, operator=None):
        self.rule_id = rule_id
        self.condition = self.create_condition(condition_requirements)
        self.operator = operator
        self.classification = classification

    def create_condition(self, requirements):
        # requirements is a dict  column : value
        condition = lambda log_entry: all(
            (log_entry.get(column) < value if self.operator == 'smaller_than'
             else log_entry.get(column) > value if self.operator == 'greater_than'
            else log_entry.get(column) == value)
            for column, value in requirements.items()
        )
        return condition

    def apply(self, log_entry):
        if self.condition(log_entry):
            return self.classification
        return None

class AdvancedRule(ABC):
    def __init__(self, rule_id):
        self.rule_id = rule_id
    @abstractmethod
    def apply(self, log):
       pass

class MultipleRequests(AdvancedRule):
    """
    scan the log and detect if the same request was made more than @num_of_times in shorter time than @time_interval
    """
    def __init__(self, rule_id, num_of_times, time_interval):
        super().__init__(rule_id)
        self.num_of_times = num_of_times
        self.time_interval = time_interval

    def apply(self, log):
        suspicous = []
        key_to_count = {}
        sorted_log = sorted(log, key=lambda entry: datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S'))
        for log_entry in sorted_log:
            key = (log_entry['source_ip'], log_entry['dest_ip'], log_entry['action'], log_entry['size'], log_entry['protocol'])
            curr_entry_time = datetime.strptime(log_entry['timestamp'], '%Y-%m-%d %H:%M:%S')
            if key not in key_to_count:
                key_to_count[key] = [1, curr_entry_time]
            else:
                count, first_time = key_to_count.get(key)
                count+=1
                key_to_count[key][0] = count
                if count >= self.num_of_times and (curr_entry_time - first_time).seconds <= self.time_interval:
                    suspicous.append(key)
                    # update the new value
                    key_to_count[key] = [count, curr_entry_time]
        return suspicous