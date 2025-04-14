# Error Log

This document provides detailed information about common errors that users might encounter while using the ThreatFlow project, along with their solutions.

## Common Errors

### 1. Splunk Connection Errors

#### Error Message
```
ConnectionError: Could not connect to Splunk server
```

#### Solution
- Ensure your Splunk instance is running and accessible.
- Verify the `splunk_ip` and `splunk_token` in your `.env` file are correct.
- Check your network connectivity to the Splunk server.

### 2. TheHive Connection Errors

#### Error Message
```
ConnectionError: Could not connect to TheHive server
```

#### Solution
- Ensure your TheHive instance is running and accessible.
- Verify the `thehive_api` and `thehive_ip` in your `.env` file are correct.
- Check your network connectivity to the TheHive server.

### 3. CSV File Errors

#### Error Message
```
FileNotFoundError: windows_eventcode.csv not found
```

#### Solution
- The `windows_eventcode.csv` file is automatically created when the Main class is initialized. Ensure the initialization process completed successfully.
- If the file is missing, reinitialize the Main class.

### 4. Poetry Installation Errors

#### Error Message
```
Command 'poetry' not found
```

#### Solution
- Ensure Poetry is installed correctly. Run `pip install poetry` to install it.
- Verify that Poetry is in your system's PATH.

### 5. Dependency Errors

#### Error Message
```
ModuleNotFoundError: No module named 'splunk-sdk'
```

#### Solution
- Ensure all dependencies are installed using Poetry. Run `poetry install` to install all dependencies.
- Verify that the correct versions of dependencies are specified in `pyproject.toml`.

## Debugging Tips

- **Check Logs**: Look for log files in the project directory for more detailed error information.
- **Verify Environment Variables**: Ensure all environment variables in `.env` are set correctly.
- **Network Connectivity**: Verify that your network allows connections to Splunk and TheHive servers.
- **Dependency Versions**: Ensure that all dependencies are compatible with each other and with your Python version.

## Additional Resources

- [Splunk Documentation](https://docs.splunk.com/)
- [TheHive Documentation](https://docs.thehive-project.org/)
- [Poetry Documentation](https://python-poetry.org/docs/) 