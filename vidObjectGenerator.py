### @author: David Wong
### @date: 09/04/2024
### Description: Script that creates V-ID objects from CKLs.


# -------- External Modules -------- 
import os
import re
import xml.etree.ElementTree as ET
from lxml import etree
import time

# -------- Global Variables --------

template_path = "C:\\Program Files\\Motorola\\FedCS\\Audit\\Resources\\template"
s3_directory = r"\\10.38.97.45\ci475316-fed-s3-storage-share\customers" #DOUBLE CHECK THIS

# -------- External Classes --------

from vidClass import VulnID, customerVulnID

# -------- Private Functions --------

#FUNCTION: PROCESS INDIVIDUAL CKL FILES AND RETURNS A LIST OF VID OBJECT
#PARAMETER: THE PATH TO THE CKL FILE (ckl)

def generic_ckl_processor(ckl):
    
    #soup = BeautifulSoup(ckl_contents, 'lxml') #using lxml for more features 
    tree = etree.parse(ckl)
    root = tree.getroot()

    #for vuln in soup.find_all('VULN'):
    vuln_objects = []
    for vuln in root.xpath('.//VULN'):
        vuln_obj = VulnID()
        for stig_data in vuln.xpath('./STIG_DATA'):
            vuln_attribute = stig_data.find('VULN_ATTRIBUTE').text
            attribute_data = stig_data.find('ATTRIBUTE_DATA').text
            if hasattr(vuln_obj, vuln_attribute.lower()):
                setattr(vuln_obj, vuln_attribute.lower(), attribute_data)
        vuln_objects.append(vuln_obj)
    return vuln_objects

##FUNCTION: IDENTIFY CKL FILES THAT HAVE BEEN RECENTLY ADDED IN THE LAST 30 DAYS. RETURN THE FILE AND THE FULL PATH.
##PARAMETER: THE S3 DIRECTORY (s3_directory)

def identify_new_ckl_files(s3_directory):
    new_ckl_files = []
    time_threshold = time.time() - 24*60*60  # 24 hours * 60 minutes * 60 seconds = 1 day

    for dirpath, dirnames, filenames in os.walk(s3_directory):
        for filename in filenames:
            if filename.endswith('.ckl'):
                full_path = os.path.join(dirpath, filename)
                print(full_path) 
                if os.path.getctime(full_path) > time_threshold:
                    new_ckl_files.append(full_path)

    return new_ckl_files


##FUNCTION: STEP THROUGH THE S3 DIRECTORY AND RETURN RESPECTIVE CUSTOMER ATTRIBUTES BASED ON LOCATION
##PARAMETER: THE CKL FILE (customer_ckl)

#TODO

def customer_folder_attribute(customer_ckl):
    #customer_name
    #customer_site
    #system_version
    #month_year

    if customer_ckl.endswith('.ckl'):
        for dirpath, dirnames, filenames in os.walk(customer_ckl):
            print('hi')
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                print(full_path)
    else:
        print("Invalid file type. Please provide a .ckl file.")


def customer_file_attribute(customer_ckl):

    #This is expected to be of the form of U_STIG_V#R#_HOSTNAME_yyyymmdd_##_initials.ckl
    #Where we are grabbing the date, hex value (two digit), and initials
    match = re.search(r"_([0-9]{8})_([0-9A-Fa-f]{2})_([A-Z]{2,3})\.ckl", customer_ckl)

    if match:
        date = match.group(1)
        hex_value = match.group(2)
        initials = match.group(3)

    return dict(date=date, hex_value=hex_value, initials=initials)

##FUNCTION: PROCESS INDIVIDUAL CUSTOMER CKL FILES AND RETURNS A LIST OF CUSTOMER VID OBJECTS
##PARAMETER: THE PATH TO THE CUSTOMER CKL FILE (customer_ckl)

def customer_ckl_processeor(customer_ckl):
    tree = etree.parse(customer_ckl)
    root = tree.getroot()

    customer_vuln_objects = []
    for customer_vuln in root.xpath('.//VULN'):
        customer_vuln_obj = customerVulnID()
        setattr(customer_vuln_obj, 'host_ip', tree.find('HOST_IP').text)

        #need to add folder and file attributes

        date, hex_value, initials = customer_file_attribute(customer_ckl)
        setattr(customer_vuln_obj, 'date', date)
        setattr(customer_vuln_obj, 'hex_value', hex_value)
        setattr(customer_vuln_obj, 'initials', initials)

        for stig_data in customer_vuln.xpath('./STIG_DATA'):
            vuln_attribute = stig_data.find('VULN_ATTRIBUTE').text
            attribute_data = stig_data.find('ATTRIBUTE_DATA').text
            if hasattr(customer_vuln_obj, vuln_attribute.lower()):
                setattr(customer_vuln_obj, vuln_attribute.lower(), attribute_data)
        customer_vuln_objects.append(customer_vuln_obj)
    return customer_vuln_objects


# -------- Public Functions --------

# -------- Main --------

def main():
    #generic_ckl_processor(template_path+'\\RHEL8_V1R14.ckl')
    #customer_folder_attribute(template_path+'\\RHEL8_V1R14.ckl')
    identify_new_ckl_files(s3_directory)

if __name__ == '__main__':
    main()