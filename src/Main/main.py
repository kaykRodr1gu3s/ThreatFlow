import sys
import os
from pathlib import Path
import splunklib
import splunklib.client
import json
import uuid
import time
import logging
from logging.handlers import RotatingFileHandler
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
from typing import Dict, Any
from requests.exceptions import RequestException

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Tools import scrapy

def setup_logging():
    log_path = project_root / "logs" / "threatflow.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=5*1024*1024,
        backupCount=3
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    logger = logging.getLogger("ThreatFlow")
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(logging.StreamHandler())
    
    return logger

logger = setup_logging()

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

    def __init__(self, max_retries: int = 3, retry_delay: int = 5):
        load_dotenv()
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.splunk_ip = os.getenv("splunk_ip")
        self.splunk_token = os.getenv("splunk_token")
        
        if not self.splunk_ip or not self.splunk_token:
            raise ValueError("Splunk IP or token not found in environment variables")
            

    def splunk_connector(self) -> None:
        """Establish connection to Splunk with retry mechanism."""
        for attempt in range(self.max_retries):
            try:
                self.splunk_client = splunklib.client.connect(
                    host=self.splunk_ip,
                    port=8089,
                    token=self.splunk_token,
                    autologin=True
                )
                logger.info("Successfully connected to Splunk")
                return
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Failed to connect to Splunk after {self.max_retries} attempts: {str(e)}")
                    raise
                logger.warning(f"Connection attempt {attempt + 1} failed, retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)

    def alert_datas(self) -> Dict[str, Any]:
        """
        Create a job in Splunk and collect the last alert with the detection rule.

        Returns:
        dict: The most recent Splunk event matching the detection rules.
        
        Raises:
        Exception: If there's an error retrieving data from Splunk
        """
        try:
            query = self._load_splunk_query()
            
            job = self.splunk_client.jobs.create(query)
            
            timeout = 60
            start_time = time.time()
            while not job.is_done():
                if time.time() - start_time > timeout:
                    job.cancel()
                    raise TimeoutError("Splunk job timed out")
                time.sleep(1)

            results = job.results(output_mode='json')
            data = json.loads(results.read().decode("utf-8"))
            job.cancel()
            
            if not data.get("results"):
                logger.warning("No results returned from Splunk query")
                return {}
                
            return data["results"][0]
        except RequestException as e:
            logger.error(f"Network error while retrieving data from Splunk: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error retrieving data from Splunk: {str(e)}")
            raise

    def _load_splunk_query(self) -> str:
        """Load and return the Splunk query from configuration."""
        return """search index=test_detection_rule index=test_detection_rule EventCode IN (4625, 4624, 4648, 4675, 4720, 4726, 4732, 4740, 4672, 4697, 4688, 4698, 7045, 5156, 5158, 4663, 4670, 1102, 4719, 7030, 7040)
            | fields EventCode, host, SourceName, _time
            | lookup windows_event_code.csv event_code AS EventCode OUTPUT event_description
            | table _time EventCode event_description host SourceName
            | where isnotnull(event_description)"""

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

    def __init__(self, max_retries: int = 3, retry_delay: int = 5):
        load_dotenv()
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.api = os.getenv("thehive_api")
        self.endpoint = os.getenv("thehive_ip")
        

    def thehive_conector(self):
        if not self.api or not self.endpoint:
            raise ValueError("TheHive API key or endpoint not found in environment variables")
            

        for attempt in range(self.max_retries):
            try:
                self.client = TheHiveApi(self.endpoint, self.api)
                logger.info("Successfully initialized TheHive client")
                return self.client
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Failed to initialize TheHive client after {self.max_retries} attempts: {str(e)}")
                    raise
                logger.warning(f"Connection attempt {attempt + 1} failed, retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)

    def create_alert_function(self, splunk_datas: Dict[str, Any]) -> None:
        """
        Create an alert in TheHive based on event data pulled from Splunk.

        Args:
            splunk_datas (dict): Dictionary containing keys like EventCode, host, _time, and SourceName.
            
        Raises:
        Exception: If there's an error creating the alert in TheHive
        """
        try:
            if not splunk_datas:
                logger.warning("No data provided to create alert")
                return
                
            event_datas = pd.read_csv(project_root / "data" / "windows_eventcode.csv")
            
            event_code = splunk_datas.get("EventCode")
            if not event_code:
                raise ValueError("EventCode not found in Splunk data")
                
            event_description = event_datas.query(f"Eventid == {event_code}")["Description"].to_string(index=False)
            see_on = event_datas.query(f"Eventid == {event_code}")["See on"].to_string(index=False)
            
            event_time = datetime.fromisoformat(splunk_datas["_time"]).strftime("%d/%m/%Y %H:%M:%S")
            
            alert = Alert(
                title=f"Splunk Alert {event_code}",
                type="external",
                source="Splunk",
                description=f"Description: {event_description}\n\nSee more on: {see_on}",
                sourceRef=f"Splunk alert: uuid: {uuid.uuid4()}",
                artifacts=[
                    AlertArtifact(dataType="host", data=splunk_datas["host"]),
                    AlertArtifact(dataType="datetime", data=event_time),
                    AlertArtifact(dataType="SourceName", data=splunk_datas["SourceName"]),
                    AlertArtifact(dataType="EventCode", data=event_code, message="EventCode")
                ]
            )

            self.client.create_alert(alert)
            logger.info(f"Successfully created alert for EventCode {event_code}")

        except RequestException as e:
            logger.error(f"Network error while creating alert in TheHive: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error creating alert in TheHive: {str(e)}")
            raise

class Main(Splunk, Thehive):
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

    def __init__(self, poll_interval: int = 60, max_retries: int = 3, retry_delay: int = 5):
        self.poll_interval = poll_interval
        Splunk.__init__(self, max_retries, retry_delay)
        Thehive.__init__(self, max_retries, retry_delay)
        self.last_ref = None
        logger.info("Main class initialized")

    def uploader(self) -> None:
        """
        Continuously polls Splunk for new alerts and sends them to TheHive if they are not duplicates.
        """
        self.thehive_conector()
        self.splunk_connector()
        try:
            windows_event_code = scrapy.Windows_EventCode()
            windows_event_code.event_codes
        except FileExistsError:
            pass


        while True:
            try:
                splunk_datas = self.alert_datas()
                if splunk_datas and splunk_datas != self.last_ref:
                    self.create_alert_function(splunk_datas)
                    self.last_ref = splunk_datas
                time.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Error in main loop: {str(e)}")
                time.sleep(self.poll_interval)

if __name__ == "__main__":
    try:
        main = Main()
        main.uploader()
    except Exception as e:
        logger.critical(f"Application failed to start: {str(e)}")

        