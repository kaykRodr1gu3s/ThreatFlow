import splunklib
import splunklib.client
import json
import os
import uuid
import time
import pandas as pd

from dotenv import load_dotenv
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

from scrapy import Windows_EventCode


class Splunk:
    """
    Handles Splunk connection and retrieves the most recent alert using predefined detection rules.

    This class creates a search job on Splunk, waits for its completion, retrieves the results in JSON format, and cancels the job afterward.

    Environment Variables:
        - splunk_ip: IP address of the Splunk instance.
        - splunk_token: Authentication token for Splunk.

    Methods:
        - alert_datas(): Executes the query and returns the latest event as a dictionary.
    """

    def __init__(self):
        load_dotenv()
        self.splunk_client = splunklib.client.connect(host=os.getenv("splunk_ip"), port=8089,token=os.getenv("splunk_token"), autologin=True)

    def alert_datas(self):
        """
        Create a job in Splunk and collect the last alert with the detection rule.

        Returns:
        dict: The most recent Splunk event matching the detection rules.
        """

        job = self.splunk_client.jobs.create("""search index=test_detection_rule EventCode IN (4625, 4624, 4648, 4675, 4720, 4726, 4732, 4740, 4672, 4697, 4688, 4698, 7045, 5156, 5158, 4663, 4670, 1102, 4719, 7030, 7040)
            | fields EventCode, host, SourceName, 
            | lookup windows_event_code.csv event_code AS EventCode OUTPUT event_description
            | table _time EventCode event_description host  SourceName
            | where isnotnull(event_description)""")
        while not job.is_done():
            time.sleep(1)

        results = job.results(output_mode='json')
        datas =json.loads(results.read().decode("utf-8"))
        job.cancel()


        return datas["results"][0]

class Thehive:
    """
    Handles alert creation in TheHive platform using data collected from Splunk.

    This class uses TheHive4py to construct and send alerts. It extracts contextual descriptions from a local CSV file and formats them into a rich alert object.

    Environment Variables:
        - thehive_ip: URL or IP of TheHive instance.
        - thehive_api: API key for TheHive authentication.

    Methods:
        - create_alert_function(splunk_datas): Builds and sends an alert to TheHive based on the Splunk event dictionary.
    """

    def __init__(self):
        self.api = os.getenv("thehive_api")
        self.endpoint = os.getenv("thehive_ip")
        self.client = TheHiveApi(self.endpoint, self.api)

    def create_alert_function(self, splunk_datas: dict):
        """
        Create an alert in TheHive based on event data pulled from Splunk.

        Args:
            splunk_datas (dict): Dictionary containing keys like EventCode, host, _time, and SourceName.
        """


        event_datas = pd.read_csv("windows_eventcode.csv", index_col=0)
        alert = Alert(
            title=f"Splunk Alert {splunk_datas["EventCode"]}",
            type="external",
            source="Splunk",
            description=f"""
            Description: {event_datas.query(f"Eventid == {splunk_datas['EventCode']}")["Description"].to_string(index=False)}
            See more on: {event_datas.query(f"Eventid == {splunk_datas['EventCode']}")["See on"].to_string(index=False)}
            """,
            sourceRef=f"""Splunk alert:
            uuid: {uuid.uuid4()}""",
            artifacts=[
            AlertArtifact(dataType="host", data=splunk_datas["host"]),
            AlertArtifact(dataType="datetime", data=splunk_datas["_time"]),
            AlertArtifact(dataType="SourceName", data=splunk_datas["SourceName"]),
            AlertArtifact(dataType="EventCode", data=splunk_datas["EventCode"], message="EventCode")
            ])
        self.client.create_alert(alert)

class Main(Splunk, Thehive, Windows_EventCode):
    """
    Main orchestrator class that integrates Splunk alert collection with TheHive alert generation.

    This class inherits from:
    - Splunk: to collect the latest security alerts from a Splunk instance
    - Thehive: to send structured alerts to TheHive
    - Windows_EventCode: to enrich alerts with human-readable event code metadata

    Responsibilities:
    - Periodically polls Splunk for new security alerts
    - Compares the new alert to the previous one
    - Sends a new alert to TheHive only if it hasn't been sent yet

    Methods:
        - uploader(): Runs the main loop that fetches alerts from Splunk and sends them to TheHive if they are new.
    """

    def __init__(self):
        Splunk.__init__(self)
        Thehive.__init__(self)
        Windows_EventCode.__init__(self)

    def uploader(self):
        """
        Continuously polls Splunk for new alerts and sends them to TheHive if they are not duplicates.

        This function:
        - Retrieves the latest alert from Splunk every 60 seconds.
        - Compares it to the last seen alert using the `_time` field.
        - If a new alert is detected, it sends it to TheHive as an external alert.
        """

        self.scrapy_datas
        last_ref = self.alert_datas()["_time"]

        while True:
            current_alert = self.alert_datas()
            if current_alert["_time"] != last_ref:
                self.create_alert_function(current_alert)
                last_ref = current_alert["_time"]
            time.sleep(60)

