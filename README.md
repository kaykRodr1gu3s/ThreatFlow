# ThreatFlow

ThreatFlow is an automation that automates the alerts from Splunk, enriches them with more context, and sends them to TheHive using Python tools and libraries.

## Index

1 - [Overview](#overview)

2 - [Key Capabilities](#key-capabilities)

3 - [Technologies Used](#technologies-used)

4 - [Workflow Breakdown](#workflow-breakdown)

5 - [Setup Instructions](#setup-instructions)

6 - [How to Use](#how-to-use)

7 - [Customizing Detection Rules](#customizing-detection-rules)

8 - [Alert in Thehive](#alert-in-thehive)


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
poetry init --no-interaction
poetry add splunk-sdk
poetry add thehive4py
poetry add thehive4py==1.8.2
poetry add pandas
```

## How to use
After cloning the repository and setting up the environment, navigate to [threatflow.py](https://github.com/kaykRodr1gu3s/ThreatFlow/blob/main/Main/threatflow.py) and initialize the Main class:

```
main = Main()
```
To start the automation, simply run:
```
main.uploader()
```

## Customizing Detection Rules

If you want to use a different detection rule in your Splunk query, update the query inside the alert_datas method at line 42 in threatflow.py.

   **Important:**
  
   **If you change the fields returned by the Splunk query, make sure to also update the alert fields used in the TheHive payload (lines 85 to 101) accordingly.
       Failing to do this may result in runtime errors.**


### Example Error
Here’s an example of an error that occurs if the field name is wrong in your Splunk query:

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

