#!/usr/bin/python
import sys
import time
import random
import json
from os.path import join as pjoin
try:
    import requests
    import argparse
    from termcolor import colored
except:
    print"Please install the dependencies first"
    print"You can install them by typing pip install -r dependencies.txt\n"
    exit()




usage = "\n\ttest1 [OPTIONS] -p 'policy_name' [-t target| -T target_file]\n"
example="""For Example:
       test1 -p 'Basic Network Scan' -t targetIP -e csv -o report.csv
       test1 -p 'Advanced Scan' -T targetFile.txt -e nessus --configure
       test1 -l
"""

parser = argparse.ArgumentParser(usage=usage,epilog=example,formatter_class=argparse.RawDescriptionHelpFormatter)
group = parser.add_mutually_exclusive_group()

parser.add_argument('-l','--list-policies',dest="list_policies",action="store_true",help="Lists all policies")
parser.add_argument('-L','--list-scan',dest="list_scan",action="store_true",help="Lists all scans")
#parser.add_argument('-E','--export-scan',dest="export_scan",action="store_true",help="Export Scan by ID")
parser.add_argument("-E  "'--export_scan',dest='export_scan',type=str,help='id of scan for report')
#parser.add_argument("-m  "'--args.monitor_scan',dest='args.monitor_scan',type=str,help='Name of scan for report')
parser.add_argument('-c','--configure',dest="configure",action='store_true',help="By specifying this flag, user will be able to configure the policy determined by -p flag before launching the scan.")
parser.add_argument('-e  ',dest="export_format",help="Export the scan report in specified format.\nThe available formats are nessus,html,csv and db.")
group.add_argument('-t  ',dest="target",help="Single target to launch scan against")
group.add_argument('-T  ',dest="target_file",help="Specifies File containing the list of targets")
parser.add_argument("-p  ",dest='policy_name',type=str,help='policy to use for nessus scan')
parser.add_argument('-o  ',dest="output",type=str,help="File to output the result.")
parser.add_argument("-n  ",dest='scan_name',type=str,help='Name to be used for the particular scan.If not specified, default value of "Scan Created by API Script" will be used.')
parser.add_argument("-d  ",'--delete',dest='delete',action='store_true',help='Delete the scan after completion.This flag can be useful when user wants to delete the scan after successfully exporting the report.')
#group.add_argument('-P', '--policies', dest='policy_list', action='store_true', help='List current policies')
group.add_argument('-s', '--start', dest='start_scan_id', type=str, help='Start a specified scan using scan id')
group.add_argument('-r', '--resume', dest='resume_scan_id', type=str, help='Resume a specified scan using scan id')
group.add_argument('-k', '--pause', dest='pause_scan_id', type=str, help='Pause a specified scan using scan id')
group.add_argument('-z', '--stop', dest='stop_scan_id', type=str, help='Stop a specified scan using scan id')

args = parser.parse_args()

#Prints help if no argument is passed
if not len(sys.argv)>1:
    parser.print_help()
    exit()


#Check the current version of python, if not python 2.x, exit.
if sys.version_info[0] != 2:
    print('This script must be run with Python version 2.x')
    exit()


#username and password for loging in 
username = "Nessus_username"
password = "Nessus_password"


#Alter the url filled if Nessus is running on a remote machine
url = "https://NessusIP:8834"

#Make it true if you want to verify the SSL certificate
verify = False


#Disables Warning when not verifying SSL certs
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

#Checks if the target is specified or configure flag is set, when -p flag is used
if args.policy_name:
    if not (args.target or args.target_file or args.configure):
        print "usage: " + usage
        print"test1 -h for more info"
        exit()

#Checks if the policy to use is defined or not, when -t or -T flag is used
if args.target or args.target_file:
    if not args.policy_name:
        print "usage: " + usage
        print"test1 -h for more info"
        exit()


#Tries to open target file if -T flag is used
if args.target_file:
    try:
        with open(args.target_file) as t:
            target=t.read()
    except IOError:
        print"Cannot open the file",args.target_file
        print"Make sure you spelled it right\n"
        exit()

#set target variable when -t flag is used
if args.target:
    target=args.target


#if --configure flag is set, configure the policy before launching the scan
if args.configure:
    if not args.policy_name:
        print"Policy name not supplied"
        print"test1 -h for more info"
        exit()

class create_menu:
    '''This is used to build an instance of the menu object
       and can be called from the main program to instantiate the menu
       with passed variables.'''
    def __init__(self, menu, text, other):
        self.text = text
        self.menu = menu
        self.other = other

        # Build the menu
        option_length_menu = len(menu)
        option_length_text = len(text)
        if self.other != 'Null':
            print('%s' + (20-option_length_menu) * ' ' + '  :    %s' + (15-option_length_text)*' ' +  ':    %s') %(menu,text,other)

        else:
            print('%s' + (15-option_length_menu) * ' ' + '  :  %s') %(menu,text)
        return
		
def connect(method, resource, data=None, params=None):
    """
    Send a request

    Send a request to Nessus based on the specified data. If the session token
    is available add it to the request. Specify the content type as JSON and
    convert the data to JSON format.
    """
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=params, headers=headers, verify=verify)

    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print e['error']
        sys.exit()

    # When downloading a scan we need the raw contents not the JSON data.
    if 'download' in resource:
        return r.content

    # All other responses should be JSON data. Return raw content if they are
    # not.
    try:
        return r.json()
    except ValueError:
        return r.content
		
def build_url(resource):
    return '{0}{1}'.format(url, resource)
	
def get_scans():
    """
    Get history ids
    Create a dictionary of scans and uuids
    """

    status_dict = {}
    name_dict = {}
    data = connect('GET', '/scans/')
    for p in data['scans']:
        status_dict[p['id']] = p['status']
        name_dict[p['id']] = p['name']
    #status_dict = dict((p['name'], p['status']) for p in data['scans'])
    #id_dict = dict((b['name'], b['id']) for b in data['scans'])

    return status_dict, name_dict


def get_history_ids(sid):
    """
    Get history ids

    Create a dictionary of scan uuids and history ids so we can lookup the
    history id by uuid.
    """
    data = connect('GET', '/scans/{0}'.format(sid))
    temp_hist_dict = dict((h['history_id'], h['status']) for h in data['history'])
    temp_hist_dict_rev = {a:b for b,a in temp_hist_dict.items()}
    try:
        for key,value in temp_hist_dict_rev.items():
            print key
            print value
    except:
        pass
    #return dict((h['uuid'], h['history_id']) for h in data['history'])


def get_scan_history(sid, hid):
    """
    Scan history details

    Get the details of a particular run of a scan.
    """
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid), params)
    return data['info']


def get_status(sid):
    # Get the status of a scan by the sid.
    # Print out the scan status

    time.sleep(3) # sleep to allow nessus to process the previous status change
    temp_status_dict, temp_name_dict = get_scans()
    print '\nScan Name           Status  '
    print '---------------------------------------'
    for key, value in temp_name_dict.items():
        if str(key) == str(sid):
            create_menu(value, temp_status_dict[key], 'Null')


def launch(sid):
    # Launch the scan specified by the sid.

    data = connect('POST', '/scans/{0}/launch'.format(sid))
    return data['scan_uuid']

def pause(sid):
    # Pause the scan specified by the sid.
    connect('POST', '/scans/{0}/pause'.format(sid))
    return

def resume(sid):
    # Resume the scan specified by the sid.
    connect('POST', '/scans/{0}/resume'.format(sid))
    return

def stop(sid):
    # Resume the scan specified by the sid.
    connect('POST', '/scans/{0}/stop'.format(sid))
    return


def login():
    """Function to log the user in by sending GET request
        with username and password to URI /session"""

    res = requests.post(url + '/session',data={'username':username,'password':password},verify=verify)
    if(res.status_code==200):
        global token
        token = res.json().get('token')
        #print "%s" %token
    else:
        print res.json()['error']
        exit()



def logout():
    """Function to log the user out by sending DELETE
        request to URI /session"""

    requests.delete(url + '/session',headers=headers,verify=verify)
    print""
    exit()



def get_policies():
    """ Function to retrieve policies:
          This Function retrieves policies in two phases:
          First it retrieves the user defined policies and then the predefined templates"""

    policies = requests.get(url + '/policies',headers=headers,verify=verify)   #Getting user defined policies
    templates = requests.get(url+"/editor/policy/templates",headers=headers,verify=False)         #Getting templates
    if policies.status_code==403 or templates.status_code==403:
        print"User don't have the permission to view the policy list"
        print"You may try logging in again with privileged account"
    if policies.status_code==200 and templates.status_code==200:
        return policies.json()['policies'],templates.json()['templates']        #return json data as tuple
    else:
        print str(policies.json()['error'])
        logout()



def policy_json_from_policy_name():
    """This function is used to get the json data from the policy name.
       The function checks for the existence of policy name supplied with -p tag
       and returns the complete json data of the file."""
    
    policies = get_policies()                                 #Getting policies as a tuple
    for policy in policies[0]:                   #checks if the policy to use is predefined-template,if so,return the policy json
        if args.policy_name==policy['name']:
            return policy
    for policy in policies[1]:                         #checks if the policy to use is user-defined, if so,return the policy json
        if args.policy_name==policy['title']:         
            return policy
    print"Cannot find the policy with name",args.policy_name
    logout()      


def delete_scan():
    print"Are you sure you want to delete the scan(y/n): ",
    answer = raw_input()
    if answer!='y' or answer!='n':
        while answer!='y' and answer!='n':
            answer = raw_input("\nPress y or n : ")
    if answer=='y':
        print"Deleting the scan"
        global scan_id
        res = requests.delete(url + '/scans/{0}'.format(scan_id),headers=headers,verify=verify)
        if res.status_code==200:
            print"Scan deleted"
        else:
            print res.json()['error']
    else:
        print"Scan not deleted"


def configure_policy():
    """Function to configure policy settings.
      This function can be useful when trying to configure the policy prior to launching the scan"""

    policy = policy_json_from_policy_name()                    #getting policy json data from its name

    try:
        policy_id=policy['id']
    except KeyError:
        print"Only User-defined policies can be configured"
        logout()

    #Getting policy configurations
    res = requests.get(url+'/policies/{0}'.format(policy['id']),verify=False,headers=headers)

    #If response is not ok, print the error and logout
    if res.status_code!=200:
        print res.json()['error']
        logout()

    #If response is ok, ensure that the discovery mode is set to custom
    if res.json()['settings']['discovery_mode']!='Custom':
        payload = res.json()
        payload['settings']['discovery_mode']="Custom"
        payload=json.dumps(payload)
        res = requests.put(url+'/policies/{0}'.format(policy['id']),verify=False,headers=headers,data=payload)

        if res.status_code!=200:
            print res.json()['error']
            logout()

    payload = requests.get(url+'/policies/{0}'.format(policy['id']),verify=False,headers=headers).json()
    print"Trying to configure the policy"
    try:
        #Configure user-defined policy at run time

        print colored("\nAnytime press Enter for default :\n",'green',attrs=['bold'])
        print "Ping the remote host" + "(default is " + payload['settings']['ping_the_remote_host']  + ") : ",
        temp = raw_input()

        #when ping the remote host option is changed, we need to get the policy json data again to handle key error

        #if ping_the_remote_host option is changed, getting the payload again
        if not (temp=="" or payload['settings']['ping_the_remote_host']==temp):
            payload['settings']['ping_the_remote_host']=temp
            payload=json.dumps(payload)
            res = requests.put(url+'/policies/{0}'.format(policy['id']),verify=False,headers=headers,data=payload)
            payload = requests.get(url+'/policies/{0}'.format(policy['id']),verify=False,headers=headers).json()


        if payload['settings']['ping_the_remote_host']=='yes':               #if pinging the remote host is enabled, ask for various pinging option
            print colored("\nPING METHODS : ",'blue',attrs=['bold'])
            print "ICMP ping" + "(default " + payload['settings']['icmp_ping']  + ") : ",
            temp = raw_input()
            if temp!="":
                payload['settings']['icmp_ping']=temp
            print "TCP ping" + "(default " + payload['settings']['tcp_ping'] + ") : ",
            temp = raw_input()
            if temp!="":
                payload['settings']['tcp_ping']=temp
            print "UDP ping" + "(default " + payload['settings']['udp_ping']  + ") : ",
            temp = raw_input()
            if temp!="":
                payload['settings']['udp_ping']=temp
            print "ARP ping" + "(default " + payload['settings']['arp_ping'] + ") : ",
            temp = raw_input()
            if temp!="":
                payload['settings']['arp_ping']=temp

        #Taking portscan range from user
        print colored("\nPORT SCAN RANGE",'blue',attrs=['bold'])
        print "Port Scan range " + "(default is " + payload['settings']['portscan_range'] + ") : ",
        temp = raw_input()
        if temp!="":
            payload['settings']['portscan_range']=temp

        #Determining which network port scanners to use
        print colored("\nNETWORK PORT SCANNERS",'blue',attrs=['bold'])
        print "TCP " + "(default " + payload['settings']['tcp_scanner']  + ") : ",
        temp = raw_input()
        if temp!="":
            payload['settings']['tcp_scanner']=temp
        print "SYN " + "(default " + payload['settings']['syn_scanner'] + ") : ",
        temp = raw_input()
        if temp!="":
            payload['settings']['syn_scanner']=temp
        print "UDP " + "(default " + payload['settings']['udp_scanner'] + ") : ",
        temp = raw_input()
        if temp!="":
            payload['settings']['udp_scanner']=temp

        #sending put request to /policies to update the changes requested
        print"Updating the policy "
        payload=json.dumps(payload)
        res = requests.put(url+'/policies/{0}'.format(policy['id']),verify=False,headers=headers,data=payload)

        if res.status_code==200:
            print"Policy updated Successfully"
        else:
            print res.json()['error']

    except KeyError:
        print "key error code executed",
        raw_input()
        exit()


def create_scan(uuid,name,targets,id):
    """This function is to create and launch the scan.
          It takes policy uuid,name for launching scan and targets """

    print"Trying to create the scan"
    payload = {        "uuid" : uuid,
                   "settings" :  {

                                 "name" : name,
                         "text_targets" : targets,
                           "launch_now" : True,
                               }
               }

    if not id=="":                  #Used when policy id is supplied
        payload["settings"]["policy_id"] = id

    payload = json.dumps(payload)
    new_scan = requests.post(url + '/scans',data=payload,headers=headers,verify=verify)
    print 'test'
    if new_scan.status_code==200:
        print colored("scan created successfully",'blue',attrs=['bold'])
        print"Launching the scan...."
        print"Scan launched"
        return new_scan.json()['scan']['id']
    else:
        print str(new_scan.json()['error'])
        logout()



def show_status(scan_id):
    print"\n" + colored('status : ','blue',attrs=['bold']) + colored('Running','green',attrs=['bold'])
    while True:
        status = requests.get(url + '/scans/' + str(scan_id),headers=headers,verify=verify)
        status = status.json()['info']['status']
        if status=='canceled':
            print"Scan has been canceled"
            print"Logging the user out"
            logout()
        if status=='paused':
            print"Scan has been paused"
            print"Logging the user out"
            logout()
        if status=='completed':
            print colored("Scan completed",'yellow',attrs=['bold'])
            break
        if status=='running':
            time.sleep(2)



def export_request(scan_id):
    """Function to request for the export of scan result.
       It takes scan ID of the scan and tries to export the report in the specified format"""

    print"Trying to export the report"
	
    if args.export_format=='csv' or args.export_format=='nessus':
        payload =  { "format" : args.export_format }
    elif args.export_format=='db':
        payload =  { "format" : args.export_format , "password":password}
    elif args.export_format=='pdf' or args.export_format=='html':
        payload = { "format":args.export_format, "chapters":"vuln_hosts_summary"}
    else:
		print"Unsupported format selected\nPlease select a valid format"
		logout()
	
    payload = json.dumps(payload)
    res = requests.post(url + '/scans/' + str(scan_id) + '/export',data=payload,verify=verify,headers=headers)
    if res.status_code==200:
        file_id = res.json()['file']
        print"Waiting for the report to be ready to download..."
        time.sleep(2)
        while export_status(scan_id,file_id) is False:
            time.sleep(1)
        export_download(scan_id,file_id)
    else:
        print res.json()['error']
        print "Scan is not completed, Please try again..."
        exit()
        #print"Waiting for 10 seconds before retrying..."
        time.sleep(10)
        export_request(scan_id)

def export_request_id(scan_id):
    """Function to request for the export of scan result.
       It takes scan ID of the scan and tries to export the report in the specified format"""

    print"Trying to export the report"
	
    if args.export_format=='csv' or args.export_format=='nessus':
        payload =  { "format" : args.export_format }
    elif args.export_format=='db':
        payload =  { "format" : args.export_format , "password":password}
    elif args.export_format=='pdf' or args.export_format=='html':
        payload = { "format":args.export_format, "chapters":"vuln_hosts_summary"}
    else:
		print"Unsupported format selected\nPlease select a valid format"
		logout()
	
    payload = json.dumps(payload)
    res = requests.post(url + '/scans/' + str(scan_id) + '/export',data=payload,verify=verify,headers=headers)
    if res.status_code==200:
        file_id = res.json()['file']
        print"Waiting for the report to be ready to download..."
        time.sleep(2)
        while export_status(scan_id,file_id) is False:
            time.sleep(1)
        export_download(scan_id,file_id)
    else:
        print res.json()['error']
        print "Scan is not completed, Please try again..."
        exit()
        #print"Waiting for 10 seconds before retrying..."
        time.sleep(10)
        export_request(scan_id)

def export_status(scan_id,file_id):
    """This function checks the status of the export file.
       It returns false until the report is ready for downloading"""

    res = requests.get(url + '/scans/{0}/export/{1}/status'.format(scan_id,file_id),headers=headers,verify=verify)
    return res.json()['status']=='ready'



def export_download(scan_id,file_id):
    """Function to download the report when it is ready"""

    print"Report is ready to download"
    print"Trying to download the report"
    res = requests.get(url + '/scans/' + str(scan_id) + '/export/' + str(file_id) +'/download',headers=headers,verify=verify)
    if res.status_code!=200:
        print res.json()['error'] + '\nTrying again'
        export_download(scan_id,file_id)
    else:
        print"Report downloaded"
        print"Storing the report downloaded"
        if args.output:
            filename = args.output
        else:
            temp_status_dict, temp_name_dict = get_scans()
            for status_id,status_value in temp_status_dict.items():
				for name_id, name_value in temp_name_dict.items():
					if status_id == name_id:
						if name_id == scan_id:
							f_name = name_value
            filename = 'nessus_{0}.{1}'.format(f_name,args.export_format)
        path_to_file = pjoin("D:/PATH TO FOLDER/New folder", filename)
        with open(path_to_file,'wb') as f:
            f.write(res.content)
        print colored("Output stored to " + filename,'green',attrs=['bold']) 

def check_duplicate(new_filename):
	temp_status_dict, temp_name_dict = get_scans()
        print 'Scan Name                  Status              ID'
        print '-------------------------------------------------'

        for status_id,status_value in temp_status_dict.items():
            for name_id, name_value in temp_name_dict.items():
                if status_id == name_id:
					if name_value == new_filename:
						return False

def resolve_name(filename):
	temp_status_dict, temp_name_dict = get_scans()
        
        for name_id, name_value in temp_name_dict.items():
            if name_value == filename:
				return name_id

            

#################***********Main Function***************#################

if __name__=='__main__':
    colors = ['blue','green','red','yellow','cyan','magenta','white']
    color = colors[random.randint(0,len(colors)-1)]
    print"\n\n"
    print " "*4 + colored("               ##############################################################",color,attrs=['bold'])
    print " "*4 +colored("              #                                                            #",color,attrs=['bold'])
    print " "*4 +colored("             #      Nessus REST API script written in python for Eric     #",color,attrs=['bold'])
    print " "*4 +colored("            #                                                            #",color,attrs=['bold'])
    print " "*4 +colored("           ##############################################################",color,attrs=['bold'])
    print""


    token = ''             #token for maintaning session after login
    login()
    headers = {'X-Cookie': 'token=' + token, 'content-type': 'application/json'}     # header containing token, it also specifies
                                                                                     # the type of data being sent is json formatted


#checks if the -l flag is set, if yes,list the policies and exit
    if args.list_policies:
        policies = get_policies()
        if not policies[0]==None:
            print"\n\n"
            print"--------------------------"
            print"   USER DEFINED POLICIES  "
            print"--------------------------\n"
            for policy in policies[0]:
                print policy['name']


        print"\n\n" +  "--------------------------"
        print          "   PRE-DEFINED TEMPLATES  "
        print          "--------------------------\n"
        for policy in policies[1]:
            print policy['title']
        logout()


#configure the policy before launching the scan, if --configure flag is set
    if args.configure:
        configure_policy()


#checks if target is specified or not while using -e flag
    if args.export_scan:
        if not (args.export_format):
            print"Please specify the export format by -e"
            print"For more info type test1 -h"
            exit()

			
#export scan result if -E flag is set
    if args.export_scan:        
	print"Id entered is %s" %args.export_scan
	report = args.export_scan        
	temp_status_dict, temp_name_dict = get_scans()
    #    print 'Scan Name                  Status              ID'
    #    print '-------------------------------------------------'

        for status_id,status_value in temp_status_dict.items():
            for name_id, name_value in temp_name_dict.items():
                if status_id == name_id:
					if name_value == report:
						create_menu(name_value,status_value, status_id)        
						export_request_id(status_id)
	
		

#if target and policy name both are specified,launch the scan
    if args.policy_name and (args.target or args.target_file):
        name = "Scan created by API script"
        if args.scan_name:
            name = args.scan_name
        if check_duplicate(name) is False:
			print"Duplicate scan name provided, Please provide new scan name..."
			print"Use -n to specify new scan name..."
			exit()
        policy = policy_json_from_policy_name()
        try:
            scan_id = create_scan(policy['template_uuid'],name,target,policy['id'])
        except KeyError:
            scan_id = create_scan(policy['uuid'],name,target,"")
        #show_status(scan_id)
        #exit()

#Try to export the scan report in specified format, when -e flag is set
    #if args.export_format:
    #    export_request(scan_id)

#Delete the scan, after successfully exporting the report
    if args.delete:
        if not args.export_format:
            print"You haven't exported the report yet"
        delete_scan()

###### Display all policies  #######
#    if args.policy_list:
#        # If -p flag is specified, print the policy list and exit
#
#        print "Printing Policies \n\n"
#        policy_dict = get_policies()
#        print 'Policy Name                              UUID'
#        print '--------------------------------------------------'
#        for title,uuid in policy_dict.items():
#            create_menu(title,uuid, 'Null')
			
###### Display all scans  #######
    if args.list_scan:
        # If -L flag is specified, print the list of scans

        temp_status_dict, temp_name_dict = get_scans()
        print 'Scan Name                  Status              ID'
        print '-------------------------------------------------'

        for status_id,status_value in temp_status_dict.items():
            for name_id, name_value in temp_name_dict.items():
                if status_id == name_id:
					create_menu(name_value,status_value, status_id)
				
		

					
###### Start the scan  #######
    if args.start_scan_id:
        # If -sS [scan_id] flag is passed, start the specified scan
        start_id = resolve_name(args.start_scan_id)
        #start_id = args.start_scan_id
        temp_status_dict, temp_name_dict = get_scans()

        # Grab the status of the scan and either resume or start based on status
        for key, value in temp_name_dict.items():
            if str(key) == str(start_id):
                if temp_status_dict[key].lower() in ['stopped', 'completed' , 'aborted', 'canceled', 'on demand', 'empty']:
                    print('Launching Scan %s') %key
                    launch(start_id)
                elif temp_status_dict[key].lower() in ['running']:
                    print('Scan already running!')
                    logout()
                else:
                    print('Scan already started or paused.')
                    print('If you need to start a previously completed scan, add "completed" to the list on line 269')
                    logout()

        # Re-grab the scans to get the updated status
        get_status(start_id)

###### Resume the scan  #######
    elif args.resume_scan_id:
        # If -sR [scan_id] flag is passed, start the specified scan
        start_id = resolve_name(args.resume_scan_id)
        #start_id = args.start_scan_id
        temp_status_dict, temp_name_dict = get_scans()

        # Grab the status of the scan and either resume or start based on status
        for key, value in temp_name_dict.items():
            if str(key) == str(start_id):
                if temp_status_dict[key].lower() in ['paused']:
                    print('Resuming Scan %s') %key
                    resume(start_id)
                elif temp_status_dict[key].lower() in ['running']:
                    print('Scan already running!')
                    logout()
                else:
                    print('Scan unable to start.')
                    print('If you need to start a previously completed scan, add "completed" to the list')
                    logout()

        # Re-grab the scans to get the updated status
        get_status(start_id)

###### Pause the scan  #######
    elif args.pause_scan_id:
        # If -pS [scan_id] flag is passed, pause the specified scan
        pause_id = resolve_name(args.pause_scan_id)
        #pause_id = args.start_scan_id
        temp_status_dict, temp_name_dict = get_scans()
        for key, value in temp_name_dict.items():
            if str(key) == str(pause_id):
                if temp_status_dict[key].lower() in ['paused']:
                    print('Scan already paused!')
                    logout()
                elif temp_status_dict[key].lower() in ['running']:
                    print('Pausing Scan %s') %key
                    pause(pause_id)
                else:
                    print('Scan unable to be paused')
                    logout()

        # Re-grab the scans to get the updated status
        get_status(pause_id)

###### Stop the scan  #######
    elif args.stop_scan_id:
        # If -sP [scan_id] flag is passed, stop the specified scan

        stop_id = resolve_name(args.stop_scan_id)
        #stop_id = args.start_scan_id
        temp_status_dict, temp_name_dict = get_scans()
        for key, value in temp_name_dict.items():
            if str(key) == str(stop_id):
                if temp_status_dict[key].lower() in ['paused', 'running']:
                    print('Stopping Scan %s') %key
                    stop(stop_id)
                    #logout()
                else:
                    print('Scan cannot be stopped!')
                    logout()

        # Re-grab the scans to get the updated status
        get_status(stop_id)
#Log the user out
    logout()
