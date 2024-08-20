# OVERVIEW
Overview
This mini-project was developed as part of my preparation for an interview with a company specializing in sensitive data classification and anomaly detection.
The project demonstrates a basic implementation of rule-based model for classifying and analyzing log entries, focusing on detecting suspicious activity and handling sensitive information.

the two json files are just emphsizing the main idea and does not intent to be considered as real existing log entries.

Structure:
  1. rule.py - class implementationof rules objects.
                The class enables to create a user-defined rule and apply method to execute the rule.
                 the initial implementation contains:
                 * Class Rule - basic rule - executed on log entry (for example - size higher than 1024B)
                 * Advanced rule - abstract class for more complex rules which will be executed on the entire log
                     MultipleRequests - rule that aims to detect consecutive requests with the same metadata during a certain time interval. 
  3. main.py - the classfication pipeline:
  4.             1.reading the rules and the log
                 2. create_rules -  create the rule objects from the rules
                 3. process_log - applying the rules to log entries and detect suspicious activity.
