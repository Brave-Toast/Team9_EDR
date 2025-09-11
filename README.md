# EDR Agent

## Overview

This repository contains a modular, multi-process Endpoint Detection and Response (EDR) agent written in Python. The agent is designed to monitor various aspects of a system, detect suspicious activities, and provide a framework for responding to threats. It is highly extensible, allowing for the easy addition of new monitoring capabilities.

## Features

*   **Modular Architecture:** The EDR is built with a modular architecture that allows for the easy addition and removal of monitoring components (monitors).
*   **Multi-Process Design:** Each monitor runs in its own process, ensuring that the failure of one monitor does not affect the others. This also allows for better resource utilization on multi-core systems.
*   **Centralized Logging:** All monitors send their logs to a central queue, which are then processed by the main agent. Logs are formatted as JSON for easy parsing and analysis.
*   **Threat Intelligence Bus:** A central message bus allows monitors to share information and threat intelligence with each other.
*   **Active Response:** The EDR can be configured to take active responses to certain threats, such as killing a process or blocking an IP address.
*   **Dynamic Configuration:** The agent's behavior is controlled by a central configuration file (`config.json`), which can be modified without restarting the agent.

## How it works

The EDR agent consists of a central `EDRAgent` class and a set of monitor classes. The `EDRAgent` is responsible for loading and managing the monitors, processing logs, and dispatching active responses. Each monitor is a subclass of the `BaseMonitor` class and is responsible for monitoring a specific aspect of the system.

### EDRAgent

The `EDRAgent` is the core of the EDR. It performs the following tasks:

1.  **Loads Configuration:** The agent starts by loading the configuration from the `config.json` file.
2.  **Sets up Logging:** It sets up a centralized logger that formats log records as JSON.
3.  **Loads and Starts Monitors:** The agent dynamically discovers and loads all monitor classes from the `monitors` directory. Each monitor is started in its own process.
4.  **Starts Threat Bus Dispatcher:** A dedicated process is started to manage the threat intelligence bus, which is a queue that allows monitors to communicate with each other.
5.  **Processes Log Queue:** The agent continuously checks the log queue for new log records from the monitors.
6.  **Dispatches Active Responses:** If a log record contains an `action` field, the agent will dispatch the corresponding active response.

### BaseMonitor

The `BaseMonitor` class is the base class for all monitors. It provides the following functionality:

*   **Configuration:** It loads the monitor-specific configuration from the `config.json` file.
*   **Logging:** It provides a `log_alert` method for sending structured log records to the main agent.
*   **Threat Intelligence:** It provides a `publish_threat_intel` method for publishing messages to the threat intelligence bus.
*   **Lifecycle Methods:** It defines `start`, `stop`, and `run` methods that are called by the main agent.

## Monitors

The EDR comes with the following monitors:

*   **File Monitor:** Monitors the file system for changes, such as file creation, deletion, and modification. It can also scan file content for suspicious patterns.
*   **Juice Shop Monitor:** Monitors the logs of an OWASP Juice Shop application for signs of web attacks and error spikes.
*   **Network Monitor:** Monitors network connections and can correlate network activity with threat intelligence from other monitors.
*   **Process Monitor:** Monitors running processes for suspicious commands and can perform health checks on specifically monitored processes.
*   **SSH Monitor:** Monitors the SSH authentication log for brute-force attacks.

## Configuration

The EDR agent is configured using the `config.json` file. This file is divided into the following sections:

*   **agent:** General agent settings, such as the agent ID and log level.
*   **platform:** The platform the agent is running on (e.g., "linux").
*   **monitoring:** This section contains the configuration for each monitor. Each monitor has its own subsection, which must be named after the monitor's `get_name()` method.
*   **detection_rules:** This section contains detection rules, such as suspicious command patterns and web attack patterns.
*   **output:** This section is not currently used, but could be used to configure the output of the EDR agent (e.g., sending alerts to a SIEM).

## Extending the EDR

To create a new monitor, you need to create a new Python file in the `monitors` directory and define a new class that inherits from `BaseMonitor`. The new class must implement the `get_name` and `run` methods.

*   **`get_name()`:** This method should return a unique name for the monitor, which should match the key in the `config.json` "monitoring" section.
*   **`run()`:** This method contains the main execution logic for the monitor. It will be called in a loop by the `BaseMonitor`'s `run_wrapper` method.

Once you have created your new monitor, you can enable it and configure it in the `config.json` file. The EDR agent will automatically discover and load the new monitor when it starts.
