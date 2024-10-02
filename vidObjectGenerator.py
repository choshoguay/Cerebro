### @author: David Wong
### @date: 09/04/2024
### Description: Script that creates V-ID objects from CKLs.


# -------- External Modules -------- 
import os
import re
import xml.etree.ElementTree as ET
from lxml import etree
import time
import hashlib

# -------- Global Variables --------

template_path = "C:\\Program Files\\Motorola\\FedCS\\Audit\\Resources\\template"
#s3_directory = r"\\10.38.97.45\ci475316-fed-s3-storage-share\customers" #DOUBLE CHECK THIS
s3_directory = "E:\\Customers" #for testing


# -------- External Classes --------

from classes.vidClass import VulnID, customerVulnID

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


'''
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

'''


##FUNCTION: STEP THROUGH THE PULLED S3 DIRECTORY AND RETURN RESPECTIVE CUSTOMER ATTRIBUTES BASED ON LOCATION
##PARAMETER: THE CKL FILE (customer_ckl) PATH

#TODO

def customer_folder_attribute(customer_ckl):

    if customer_ckl.endswith('.ckl'):

        parts = customer_ckl.split(os.sep)

        organization = parts[5] #DoD
        system = parts[6] #USAF
        site = parts[7] #DAF ELMR USTX
        system_version = parts[8] #A2022.HS
        quaterly_audit = parts[10]+parts[11] #2024+Q2 --> 2024Q2
        ckl = parts[14] # ####.ckl

        return dict(organization=organization, system=system, site=site, system_version=system_version, quaterly_audit=quaterly_audit, ckl=ckl)
    else:
        print("Invalid file type. Please provide a .ckl file.")


##FUNCTION: STEP THROUGH THE S3 DIRECTORY AND RETURN RESPECTIVE FILE ATTRIBUTES 
##PARAMETER: THE CKL FILE (customer_ckl) PATH

def customer_file_attribute(customer_ckl):

    date_patterns = [
        r"_([0-9]{4}(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1]))",  # YYYYmmdd
        r"_([0-9]{4}(0[1-9]|[1-2][0-9]|3[0-1])(0[1-9]|1[0-2]))",  # YYYYddmm
        r"_((0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])[0-9]{4})",  # mmddYYYY
        r"_((0[1-9]|[1-2][0-9]|3[0-1])(0[1-9]|1[0-2])[0-9]{4})",  # ddmmYYYY
        r"_([0-9]{2}[A-Za-z]{3}(0[1-9]|[1-2][0-9]|3[0-1]))",  # YYbbdd
        r"_([0-9]{2}(0[1-9]|[1-2][0-9]|3[0-1])[A-Za-z]{3})",  # YYddbb
        r"_([0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1]))",  # YYmmdd
        r"_([0-9]{2}(0[1-9]|[1-2][0-9]|3[0-1])(0[1-9]|1[0-2]))",  # YYddmm
        r"_((0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])[0-9]{2})",  # mmddYY
        r"_((0[1-9]|[1-2][0-9]|3[0-1])(0[1-9]|1[0-2])[0-9]{2})",  # ddmmYY
        r"_([0-9]{4}[A-Za-z]{3}(0[1-9]|[1-2][0-9]|3[0-1]))",  # YYYYbbdd
        r"_([0-9]{4}(0[1-9]|[1-2][0-9]|3[0-1])[A-Za-z]{3})",  # YYYYddbb
        r"_([A-Za-z]{3}(0[1-9]|[1-2][0-9]|3[0-1])[0-9]{4})",  # bbddYYYY
        r"_((0[1-9]|[1-2][0-9]|3[0-1])[A-Za-z]{3}[0-9]{4})",  # ddbbYYYY
    ] 

    path = customer_ckl #full file path 
    ckl = os.path.basename(customer_ckl) #filename
    #This is expected to be of the form of U_STIG_V#R#_HOSTNAME_yyyymmdd_##_initials.ckl
    #Where we are grabbing the date, hex value (two digit), and initials
    #match = re.search(r"_([0-9]{8})_([0-9A-Fa-f]{2})_([A-Z]{2,3})\.ckl", ckl)
    for date_pattern in date_patterns:
        pattern = date_pattern + r"_([A-Z]{2,3})\.ckl"
        match = re.search(pattern, ckl)
        if match and ckl.endswith('.ckl'):
            date = match.group(1)
            #hex_value = match.group(2)
            #initials = match.group(3)
            initials = match.group(2)

            with open(path, 'rb') as f:
                bytes = f.read()
                readable_hash = hashlib.sha256(bytes).hexdigest()

            #return dict(date=date, hex_value=hex_value, initials=initials, hash=readable_hash)
            return dict(date=date, initials=initials, hash=readable_hash)
                
    print("Invalid file type or error with formatting." )
    return


    

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
    #identify_new_ckl_files(s3_directory)
    #for file in s3_directory:

    file = 'C:\\Users\\Public\\Downloads\\New_CKLs\\Customers\\DoD\\USAF\\DAF ELMR USTX\\A2022.HS\\Quarterly Audits\\2024\\Q2\\Working\\CKLs Completed\\._U_MS_Windows_10_V2R9_Z001S022OP01_20240708_MJ.ckl'

    #print(customer_file_attribute(file))

    #folder_attr = customer_folder_attribute(file)
        #file_attr = customer_file_attribute(file)

    # %%
    import re

    s = "._U_MS_Windows_10_V2R9_Z001S022OP01_20240708_MJ.ckl"

    match = re.search(r"_([0-9]{8})_([A-Z]{2})\.ckl", s)

    if match:
        date = match.group(1)
        initials = match.group(2)
        print(date, initials)


if __name__ == '__main__':
    main()