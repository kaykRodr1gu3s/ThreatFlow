# ThreatFlow

ThreatFlow is an automation that automates the alerts from Splunk, enriches them with more context, and sends them to TheHive using Python tools and libraries.

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Technologies Used](#technologies-used)
- [Workflow Breakdown](#workflow-breakdown)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [How to Use](#how-to-use)
- [Customizing Detection Rules](#customizing-detection-rules)
- [Alert in TheHive](#alert-in-thehive)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Quick Start](#quick-start)
- [Testing](#testing)

## Overview 

This project automates the flow of security alerts from Splunk (SIEM) to TheHive (SOAR). It polls Splunk for critical Windows security events, enriches them with human-readable context scraped from [UltimateWindowsSecurity.com](UltimateWindowsSecurity.com), and sends them as actionable alerts to TheHive.

Ideal for: for SOC teams and threat hunters who want to minimize manual triage and speed up incident response.


## Key Capabilities

+ Polls Splunk for new alerts every 60 seconds
+ Enriches alerts using scraped CSV with event descriptions
+ Builds rich alerts with context, references, and artifacts
+ Sends alerts directly to TheHive via its API
+ Prevents duplicate alerts using timestamp-based comparison

## Technologies Used

| Technology | Purpose |
| ---------- | --------------- |
|Python 3.x | Core language for the project |
|Splunk + [splunklib](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/) | Collecting and filtering security logs |
| TheHive + [thehive4py](https://thehive-project.github.io/TheHive4py/latest/) | Sending alerts via TheHive's API |
| BeautifulSoup + requests + re | Scraping event metadata from HTML |
| pandas | CLooking up and enriching events from CSV |
| python-dotenv | 	Managing environment variables securely | 
| uuid | Generating unique alert references |

## Workflow Breakdown

**1 - Scrape Event Descriptions**

 - Scrapes [UltimateWindowsSecurity.com](UltimateWindowsSecurity.com) for Event IDs and links.

 - Saves data to `windows_eventcode.csv`.

**2 - Poll Splunk for New Alerts**

 - Every 60 seconds, runs a Splunk search to retrieve the latest security events matching specific EventCodes.

**3 - Compare & Deduplicate**

 - Compares the `_time` of the latest alert with the previous one.

 - Skips processing if the alert is a duplicate.

**4 - Enrich the Alert**

 - Looks up the EventCode in `windows_eventcode.csv.`

 - Adds a human-readable description and a reference link to Microsoft Docs.

**5 - Send to TheHive**

 - Uses thehive4py to send a structured alert with relevant artifacts.
 - The alert appears in TheHive, ready for triage and investigation.

**6 - Loop**

 - The entire process repeats every 60 seconds.

## Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.x
- Splunk Enterprise
- TheHive
- Poetry (for dependency management)
- Git

## Setup Instructions

To get started, clone the repository:

```
git clone https://github.com/kaykRodr1gu3s/ThreatFlow 
```

Then, navigate to the Main directory and create a .env file with the following content:
```
splunk_ip = "SPLUNK_IP_HERE"
splunk_token = "SPLUNK_TOKEN_HERE"
thehive_api = "THEHIVE_API_KEY_HERE"
thehive_ip = "THEHIVE_URL_HERE"
```

### Installations guide
Install the required Python libraries using [Poetry](https://python-poetry.org/):
```
pip install poetry
poetry install
poetry shell
```


## Customizing Detection Rules

If you want to use a different detection rule in your Splunk query, update the query inside the alert_datas method at line 42 in threatflow.py.

   **Important:**
  
   **If you change the fields returned by the Splunk query, make sure to also update the alert fields used in the TheHive payload (lines 85 to 101) accordingly.
       Failing to do this may result in runtime errors.**


### Example Error
Here's an example of an error that occurs if the field name is wrong in your Splunk query:

```
Traceback (most recent call last):
  File "threatflow.py", line 148, in <module>
    main.uploader()
  File "threatflow.py", line 133, in uploader
    last_ref = self.alert_datas()["_times"]
                             ~~~~~~~~~~~~^^
KeyError: '_times'

```

## Alert in thehive

When an alert is triggered, TheHive will generate an alert preview similar to this example.

![image](https://github.com/user-attachments/assets/503cfcba-0532-4f1b-b0e5-bd091dada72b)

## Troubleshooting

### Common Issues

1. **Splunk Connection Issues**
   - Ensure your Splunk instance is running and accessible
   - Verify your Splunk token and IP address in the `.env` file
   - Check your network connectivity

2. **TheHive Connection Issues**
   - Verify your TheHive API key and URL
   - Ensure TheHive is running and accessible
   - Check your network connectivity

3. **CSV File Issues**
   - The `windows_eventcode.csv` file is automatically created when the Main class is initialized
   - If you need to update the CSV content, you can manually modify it

### Error Messages

For more detailed error messages and solutions, refer to the [Error Log]([error_log.md](https://github.com/kaykRodr1gu3s/ThreatFlow/blob/main/src/logs/error_log.md)).

## Quick Start

Follow these steps to get started quickly:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/kaykRodr1gu3s/ThreatFlow
   cd ThreatFlow
   ```

2. **Set Up Environment Variables**:
   Create a `.env` file in the Main directory with the following content:
   ```
   splunk_ip = "SPLUNK_IP_HERE"
   splunk_token = "SPLUNK_TOKEN_HERE"
   thehive_api = "THEHIVE_API_KEY_HERE"
   thehive_ip = "THEHIVE_URL_HERE"
   ```

3. **Install Dependencies with Poetry**:
   ```bash
   pip install poetry
   poetry init --no-interaction
   poetry add splunk-sdk thehive4py==1.8.2 pandas
   ```

4. **Run the Project**:
   ```bash
   poetry run python Main/threatflow.py
   ```
## Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Project Link**: [https://github.com/kaykRodr1gu3s/ThreatFlow](https://github.com/kaykRodr1gu3s/ThreatFlow)
- **Linkedin**: [Linkedin](www.linkedin.com/in/kayk-rodrigues-504a03273)
