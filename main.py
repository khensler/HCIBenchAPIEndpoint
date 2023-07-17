import requests
import json
from typing import Union
from fastapi import FastAPI, HTTPException, Response, Depends, File, UploadFile
from pydantic import BaseModel
from uuid import UUID, uuid4
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters

class SessionData(BaseModel):
    HCIUser: str
    HCIPass: str
    HCIServer: str
    #HCIBenchAPI: HCIBenchAPI

class HCI_Config(BaseModel):
    vcenterIp: str
    vcenterName: str
    vcenterPwd: str
    dcenterName: str
    clusterName: str
    rpName: Union[str, None]= None
    fdName: Union[str, None]= None 
    networkName: str
    staticIpprefix: Union[str, None]= None
    staticEnabled: str = "false"
    dstoreName: str
    deployHosts: Union[str, None] = "false"
    hostCredential: Union[str, None] = "{}"
    workloads: str = "4k70r,4k100r,8k50r,256k0r"
    easyRun: Union[str, None] = "false"
    vsanDebug: Union[str, None] = "false"
    clearCache: Union[str, None] = "false"
    storagePolicy: Union[str, None]= None 
    vmPrefix: str
    vmNum: int
    cpuNum: int
    ramSize: int
    diskNum: int
    diskSize: int
    reuseVM: str = "false"
    filePath: str 
    outPath: str
    warmUp: str = "NONE"
    tool: str = "fio"
    duration: str= "600"
    multiWriter: str = "false"
    selectVdbench: str = "Use All"
    cleanUp: str = "false"
    hosts: str = ""

    

cookie_params = CookieParameters()

# Uses UUID
cookie = SessionCookie(
    cookie_name="cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key="DONOTUSE",
    cookie_params=cookie_params,
)

backend = InMemoryBackend[UUID, SessionData]()

class BasicVerifier(SessionVerifier[UUID, SessionData]):
    def __init__(
        self,
        *,
        identifier: str,
        auto_error: bool,
        backend: InMemoryBackend[UUID, SessionData],
        auth_http_exception: HTTPException,
    ):
        self._identifier = identifier
        self._auto_error = auto_error
        self._backend = backend
        self._auth_http_exception = auth_http_exception

    @property
    def identifier(self):
        return self._identifier

    @property
    def backend(self):
        return self._backend

    @property
    def auto_error(self):
        return self._auto_error

    @property
    def auth_http_exception(self):
        return self._auth_http_exception

    def verify_session(self, model: SessionData) -> bool:
        """If the session exists, it is valid"""
        return True


verifier = BasicVerifier(
    identifier="general_verifier",
    auto_error=True,
    backend=backend,
    auth_http_exception=HTTPException(status_code=403, detail="invalid session"),
)

description = """
This is a front end for the HCI Bench tool. It allows you to upload a config file and run the tool.

The tool is run by first sending a POST request to /create_session with the following parameters:
- HCIUser: The username for the HCI Bench server
- HCIPass: The password for the HCI Bench server
- HCIServer: The IP address of the HCI Bench server

This will create a session and return a cookie. This cookie must be sent with all subsequent requests.

To verify that the login is valid, send a POST request to /verify_login.

To upload a config file, send a POST request to /upload_fio_file with the following parameters:
- file: The config file to upload

To get a list of the current config files, send a GET request to /get_fio_file

To delete a config file, send a POST request to /delete_fio_file with the following parameters:
- file: The config file to delete

To set the HCI Bench config, send a POST request to /set_hci_config with the following parameters:
- vcenterIp: The IP address of the vCenter server (required)
- vcenterName: The username for the vCenter server (required)
- vcenterPwd: The password for the vCenter server (required)
- dcenterName: The name of the datacenter to use (required)
- clusterName: The name of the cluster to use (required)
- rpName: The name of the resource pool to use
- fdName: The name of the folder to use
- networkName: The name of the network to use (required)
- staticIpprefix: The IP prefix to use for static IPs [true/false]
- staticEnabled: Whether or not to use static IPs [true/false]
- dstoreName: The name of the datastore to use (required)
- deployHosts: Whether or not to deploy hosts [true/false]
- hostCredential: The host credentials to use
- workloads: The workloads to use
- easyRun: Whether or not to use easy run [true/false]
- vsanDebug: Whether or not to use vsan debug [true/false]
- clearCache: Whether or not to clear the cache [true/false]
- storagePolicy: The storage policy to use
- vmPrefix: The prefix to use for VM names (required)
- vmNum: The number of VMs to use (required)
- cpuNum: The number of CPUs to use (required)
- ramSize: The amount of RAM to use (required)
- diskNum: The number of disks to use (required)
- diskSize: The size of the disks to use (required)
- reuseVM: Whether or not to reuse VMs (required) [true/false]
- filePath: The path to the config file to use
- outPath: The path to the output file (required)
- warmUp: The warm up to use (required) [true/false]
- tool: The tool to use (required)
- duration: The duration to use (required)
- multiWriter: Whether or not to use multi writer (required) [true/false]
- selectVdbench: The config file to use or "Use All" (required)
- cleanUp: Whether or not to clean up [true/false]
- hosts: The hosts to use

To validate the HCI Bench config, send a POST request to /validate_hci_config

To run the test with the current config, send a POST request to /runtest

To read the current log file, send a GET request to /readlog

To check if the test if finished, send a GET request to /istestfinish

To end the test, send a POST request to /killtest
"""

tags_metadata = [
    {
        "name": "Create Session",
        "description": "Create a session"
    },
    {
        "name": "Delete Session",
        "description": "Delete a session"
    },
    {
        "name": "Verify Login",
        "description": "Verify the login to HCI Bench"
    },
    {
        "name": "Upload FIO File",
        "description": "Upload a FIO config file"
    },
    {
        "name": "Get FIO File",
        "description": "Get a list of FIO config files"
    },
    {
        "name": "Delete FIO File",
        "description": "Delete a FIO config file"
    },
        {
        "name": "Get HCI Config",
        "description": "Get the HCI Bench config"
    },
    {
        "name": "Save HCI Config",
        "description": "Set the HCI Bench config"
    },
    {
        "name": "Validate HCI Config",
        "description": "Validate the HCI Bench config"
    },
    {
        "name": "Run Test",
        "description": "Run the test"
    },
    {
        "name": "Read Log",
        "description": "Read the log file"
    },
    {
        "name": "Is Test Finished",
        "description": "Check if the test is finished"
    },
    {
        "name": "Kill Test",
        "description": "Kill the test"
    },
    {
        "name": "Cleanup VMs",
        "description": "Delete the VMs"
    }
]

app = FastAPI(title="HCI Bench Rest API", description=description, version="1.0.0",openapi_tags=tags_metadata, port=8000,arbitrary_types_allowed=True)



@app.post("/create_session",tags=["Create Session"])
async def create_session(HCIUser: str, HCIPass: str, HCIServer: str,response: Response):

    session = uuid4()
    data = SessionData(HCIUser=HCIUser, HCIPass=HCIPass, HCIServer=HCIServer)
    await backend.create(session, data)
    cookie.attach_to_response(response, session)
    return f"created session" 

@app.post("/delete_session", tags=["Delete Session"], dependencies=[Depends(cookie)])
async def del_session(response: Response, session_id: UUID = Depends(cookie)):
    await backend.delete(session_id)
    cookie.delete_from_response(response)
    return "deleted session"

@app.post("/verify_login", tags=["Verify Login"], dependencies=[Depends(cookie)])
async def verify_login(session_data: SessionData = Depends(verifier)):
    response = HCI_login(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != "200"):
        raise HTTPException(status_code=response.status_code,detail=str(response.content))
    return

@app.post("/upload_fio_file", dependencies=[Depends(cookie)],tags=["Upload FIO File"])
async def upload_fio_file(file: UploadFile = File(...), session_data: SessionData = Depends(verifier)):
    response = HCI_UploadFIOFile(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer, file)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return response.content

@app.get("/get_fio_file", dependencies=[Depends(cookie)],tags=["Get FIO File"])
async def get_fio_file(session_data: SessionData = Depends(verifier)):
    return HCI_GetFIOFiles(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)

@app.post("/delete_fio_file", dependencies=[Depends(cookie)], tags=["Delete FIO File"])
async def delete_fio_file(filename: str, session_data: SessionData = Depends(verifier)):
    response = HCI_DeleteFIOFile(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer, filename)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return response.content

@app.post("/save_hci_config", dependencies=[Depends(cookie)],tags=["Save HCI Config"])
async def save_hci_config(hci_config: HCI_Config = Depends(), session_data: SessionData = Depends(verifier)):
    response = HCI_SaveConfig(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer, hci_config)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return response.content

@app.get("/get_hci_config", dependencies=[Depends(cookie)],tags=["Get HCI Config"])
async def get_hci_config(session_data: SessionData = Depends(verifier)):
    response = HCI_ReadConfig(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return json.loads(response.content)

@app.post("/validate_hci_config", dependencies=[Depends(cookie)],tags=["Validate HCI Config"])
async def validate_hci_config(session_data: SessionData = Depends(verifier)):
    response = HCI_ValidateConfig(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200 or str(response.content).lower().find("error") > 0):
        if(response.status_code == 200):
            status_code = 500
        else:
            status_code = response.status_code
        raise HTTPException(status_code=status_code,detail=str(response.content))
    return response.content

@app.post("/run_test", dependencies=[Depends(cookie)],tags=["Run Test"])
async def runtest(session_data: SessionData = Depends(verifier)):
    response = HCI_RunTest(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return response.content

@app.get("/read_log", dependencies=[Depends(cookie)],tags=["Read Log"])
async def readlog(session_data: SessionData = Depends(verifier)):
    response = HCI_ReadLog(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return json.loads(response.content)['data']

@app.get("/is_test_finished", dependencies=[Depends(cookie)],tags=["Is Test Finished"])
async def istestfinish(session_data: SessionData = Depends(verifier)):
    response = HCI_IsTestFinish(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200 or json.loads(response.content)["data"] == "404"):
        if(response.status_code == 200):
            status_code = int(json.loads(response.content)["data"])
        else:
            status_code = response.status_code
        raise HTTPException(status_code=status_code, detail=str(response.content))
    return response.content

@app.post("/kill_test", dependencies=[Depends(cookie)],tags=["Kill Test"])
async def killtest(session_data: SessionData = Depends(verifier)):
    response = HCI_KillTest(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200):
        raise HTTPException(status_code=response.status_code, detail=str(response.content))
    return response.content

@app.post("/cleanup_vms", dependencies=[Depends(cookie)],tags=["Cleanup VMs"])
async def cleanupvms(session_data: SessionData = Depends(verifier)):
    response = HCI_CleanupVMs(session_data.HCIUser, session_data.HCIPass, session_data.HCIServer)
    if(response.status_code != 200 or json.loads(response.content)["status"] == "500"):
        if(response.status_code == 200):
            status_code = int(json.loads(response.content)["status"])
        else:
            status_code = response.status_code
        raise HTTPException(status_code=status_code, detail=str(response.content))
    return response.content


def HCI_login(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/"
    session = requests.Session()
    session.auth = (HCIUser, HCIPass)
    session.verify = False
    response = session.get(url)
    return response

def HCI_UploadFIOFile(HCIUser: str, HCIPass: str, HCIServer: str, file):
    print(file.filename)
    print(file.content_type)
    url = "https://"+HCIServer+":8443/VMtest/uploadParamfile"
    #print(requests.Request('POST',url, files={"paramfile":(file.filename,file.file,"application/octet-stream")}, data={"tool":"fio"},auth=(HCIUser, HCIPass)).prepare().body.decode('ascii'))
    response = requests.post(url, files={"paramfile":(file.filename,file.file,"application/octet-stream")}, data={"tool":"fio"},auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_GetFIOFiles(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/getvdbenchparamFile"
    response = requests.post(url, data={"tool":"fio"},auth=(HCIUser, HCIPass),verify=False)
    json_response = json.loads(response.content)['data']
    return json_response

def HCI_DeleteFIOFile(HCIUser: str, HCIPass: str, HCIServer: str, filename: str):
    url = "https://"+HCIServer+":8443/VMtest/deleteFile"
    print(requests.Request('POST',url, data={"tool":"fio","name":filename},auth=(HCIUser, HCIPass)).prepare().body)
    response = requests.post(url, data={"tool":"fio","name":filename},auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_ReadConfig(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/readconfigfile"
    response = requests.get(url, auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_SaveConfig(HCIUser: str, HCIPass: str, HCIServer: str, config: HCI_Config):
    url = "https://"+HCIServer+":8443/VMtest/generatefile"
    config1 ={"vcenterIp":config.vcenterIp,
        "vcenterName":config.vcenterName,
        "vcenterPwd":config.vcenterPwd,
        "dcenterName":config.dcenterName,
        "clusterName":config.clusterName,
        "rpName":config.rpName,
        "fdName":config.fdName,
        "networkName":config.networkName,
        "staticIpprefix":config.staticIpprefix,
        "staticEnabled":config.staticEnabled,
        "dstoreName":config.dstoreName,
        "deployHost":config.deployHosts,
        "hosts":config.hosts,
        "workloads":config.workloads,
        "hostsCredential":config.hostCredential,
        "easyRun":config.easyRun,
        "clearCache":config.clearCache,
        "vsanDebug":config.vsanDebug,
        "storagePolicy":config.storagePolicy,
        "vmPrefix":config.vmPrefix,
        "vmNum":config.vmNum,
        "cpuNum":config.cpuNum,
        "ramSize":config.ramSize,
        "diskNum":config.diskNum,
        "diskSize":config.diskSize,
        "reuseVM":config.reuseVM,
        "filePath":config.filePath,
        "outPath":config.outPath,
        "warmUp":config.warmUp,
        "tool":config.tool,
        "duration":config.duration,
        "cleanUp":config.cleanUp,
        "multiWriter":config.multiWriter,
        "selectVdbench":config.selectVdbench
    }
    response = requests.post(url, data=dict(config),auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_ValidateConfig(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/validatefile"
    response = requests.post(url,auth=(HCIUser, HCIPass),verify=False)
    return json.loads(response.content)['data']

def HCI_CleanupVMs(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/cleanupvms"
    response = requests.post(url,auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_RunTest(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/runtest"
    response = requests.post(url,auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_ReadLog(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/readlog"
    response = requests.get(url,auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_IsTestFinish(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/istestfinish"
    response = requests.get(url,auth=(HCIUser, HCIPass),verify=False)
    return response

def HCI_KillTest(HCIUser: str, HCIPass: str, HCIServer: str):
    url = "https://"+HCIServer+":8443/VMtest/killtest"
    response = requests.post(url,auth=(HCIUser, HCIPass),verify=False)
    return response