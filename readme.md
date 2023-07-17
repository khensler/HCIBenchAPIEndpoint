# HCI Bench Rest API Server (Python)
## Description
This is a simple REST API server for the HCI Bench. It is written in Python and uses the fastapi framework. It is intended to be used with HCI Bench 2.6.x and later.
## Installation
Install the required Python packages from requirements.txt

```pip install -r requirements.txt```

## Usage
Run the server with the following command:

```uvicorn main:app --reload```

The server will listen on port 8000 by default. You can change this by editing the main.py file.

## API Documentation
The API documentation is available at http://localhost:8000/docs