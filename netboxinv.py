'''Basic Nornir job that goes through Netbox inventory including filter parameters
   Note: You can also apply filter parameters to the config.yaml as needed.'''

from nornir import InitNornir
from rich import print as rprint
import json

nr = InitNornir(config_file="config.yaml") #Initialize Nornir

def pullinfonetbox(task): #First function will display the objects within Netbox. Displaying host, hostname(IP), platform and all their respective data.
    host = task.host
    rprint(f"This host is {host}")
    rprint(f"The host name is {host.hostname}")
    rprint(f"The platform is {host.platform}")   
    rprint(json.dumps(host.data, indent=4))
nr.run(task=pullinfonetbox)

def filterplatform(tasktwo): #Second function will apply a filter prior to going through objects.
    host = tasktwo.host
    rprint(host)
ios_filter = nr.filter(platform="ios")
ios_filter.run(task=filterplatform)

def filterinfunc(taskthree): #Third function will filter through the data post-gather. In host.get, apply the Netbox API Parameters
    host = taskthree.host
    for gettags in host.get("tags",[]):
       if gettags['id'] == 23:
          print(host.hostname)
nr.run(task=filterinfunc)