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
from utilities.cklCleaner import cleanMe

# -------- Private Functions --------

#FUNCTION: PROCESS INDIVIDUAL CKL FILES AND RETURNS A LIST OF VID OBJECTS
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

##FUNCTION: PROCESS INDIVIDUAL CUSTOMER CKL FILES AND RETURNS A LIST OF CUSTOMER VID OBJECTS
##PARAMETER: THE PATH TO THE CUSTOMER CKL FILE (customer_ckl)

def customer_ckl_processeor(customer_ckl):

    #Check if the file exists
    if not os.path.exists(customer_ckl):
        #print(f"File {customer_ckl} does not exist.")
        return  None

    try: 

        customer_ckl = cleanMe(customer_ckl)

        #with open(customer_ckl, 'r', encoding='utf-8') as file:
        #    ckl_contents = file.read().strip()
        #    if not ckl_contents:
        #        print("Empty file. Please check the file.")
        #        return None

        if customer_ckl is not None:

            root = etree.fromstring(customer_ckl.encode('utf-8'))
            #root = tree.getroot()

            file_attributes = customer_file_attribute(customer_ckl)
            if not file_attributes:
                return None

            customer_vuln_objects = []
            for customer_vuln in root.xpath('.//VULN'):
                customer_vuln_obj = customerVulnID()

                #grabbing host ip if it exists
                host_ip_element = root.find('HOST_IP')
                if host_ip_element is not None:
                    setattr(customer_vuln_obj, 'host_ip', host_ip_element.text)
                else:
                    setattr(customer_vuln_obj, 'host_ip', None)

                #need to add folder and file attributes

                setattr(customer_vuln_obj, 'filename', file_attributes['filename'])
                setattr(customer_vuln_obj, 'date', file_attributes['date'])
                setattr(customer_vuln_obj, 'hash', file_attributes['hash'])
                setattr(customer_vuln_obj, 'initials', file_attributes['initials'])

                for stig_data in customer_vuln.xpath('./STIG_DATA'):
                    vuln_attribute = stig_data.find('VULN_ATTRIBUTE').text
                    attribute_data = stig_data.find('ATTRIBUTE_DATA').text
                    if hasattr(customer_vuln_obj, vuln_attribute.lower()):
                        setattr(customer_vuln_obj, vuln_attribute.lower(), attribute_data)   
                customer_vuln_objects.append(customer_vuln_obj)
            return customer_vuln_objects
    
    except (etree.XMLSyntaxError, UnicodeDecodeError) as e:
        print(f"Error parsing {customer_ckl}: {e}")
        return  None


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

    regexes = {
        "organization" : r"^(DoD|CIV_LEA|Motorola|State&Local)$",
        "system": r"^(Army|DLA|Navy|USAF|USMC|BEP_TIGTA|Boeing_NRO|CBP|CDC|Coast Guard|Coast_Guard|CRSU|DoE|DOJ USMS|DOS WARN|FBI|FEMA|ICE|NASA Goddard Space Flight Center|NASA Marshall|NIH|NPS|OPC1|OSC Donovan|PANTEX|Raytheon|Senate_JAWS|TVA|US_Capitol_Police|USMS)",
        "site:": r"^(DAF ELMR|E2LMR|Fort |Camp |ACE)",
        "system_version":r"^(A\d{4}\.\{1-3}|A\d{4}|\d{1}\.\d{2})",
        "quarterly_audit" : r"^\d{4}Q[1-4]$",
        "quarterly_audit_year" : r"^\d{4}$",
        "quarterly_audit_quarter" : r"^Q[1-4]$",
    }

    matched_items = {}

    if customer_ckl.endswith('.ckl'):

        parts = customer_ckl.split(os.sep)

        for part in parts:
            for name, regex in regexes.items():
                if re.match(regex, part):
                    matched_items[name] = part

        audit_year = matched_items.get('quarterly_audit_year')
        audit_quarter = matched_items.get('quarterly_audit_quarter')
        #quarterly_audit = matched_items.get('quarterly_audit')

        if audit_year is not None and audit_quarter is not None:
            matched_items['quarterly_audit'] = audit_year + audit_quarter
        

        return matched_items
        #return(parts)
        #return dict(organization=organization, system=system, site=site, system_version=system_version, quaterly_audit=quaterly_audit, ckl=ckl)
    #else:
        #print("Invalid file type. Please provide a .ckl file.")


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
        date_match = re.search(date_pattern, ckl)
        #match = re.search(pattern, ckl)
        if date_match and ckl.endswith('.ckl'):
            date = date_match.group(1)
            remaining_filename = ckl[date_match.end():]
            initials_match = re.search(r"_([A-Za-z]{2,3})\.ckl", remaining_filename) #initials can be 3 letters upper or lowercase
            if initials_match:
                initials = initials_match.group(1)
            else:
                #print("Initials not found. Please check the file name.")
                initials = "XX"

            with open(path, 'rb') as f:
                bytes = f.read()
                readable_hash = hashlib.sha256(bytes).hexdigest()

            if not all([ckl, date, initials, readable_hash]):
                return
            #return dict(date=date, hex_value=hex_value, initials=initials, hash=readable_hash)
            return dict(filename=ckl, date=date, initials=initials, hash=readable_hash)
                
    #print("Invalid file type or error with formatting." )
    return

## FUNCTION: ADDS ATTRIBUTES TO EXISTING OBJECTS
## PARAMETER: LIST OF EXISTING OBJECTS, DICTIONARY OF ATTRIBUTES TO ADD

def add_attributes_to_objects(objects, attributes):
    for obj in objects:
        for attr, value in attributes.items():
            setattr(obj, attr, value)

## FUNCTION: PULL EVERYTHING TOGETHER AND FINALIZE OBJECTS
## PARAMETER: NONE

def finalize_objects():
    #generic_ckl_processor(template_path+'\\RHEL8_V1R14.ckl')
    #customer_folder_attribute(template_path+'\\RHEL8_V1R14.ckl')
    #identify_new_ckl_files(s3_directory)
    count = 0
    for dirpath, dirnames, filenames in os.walk(s3_directory):
        for filename in filenames:
            if filename.endswith('.ckl'):
                count += 1
                file = os.path.join(dirpath, filename)
                file_attr = customer_file_attribute(file)
                folder_attr = customer_folder_attribute(file)
                if len(folder_attr) != 7:
                    continue
                else:
                    #calling the customer_ckl_processor function which returns a list of customer vid objects per ckl
                    customer_vid_objects = customer_ckl_processeor(file)
                    if customer_vid_objects is not None:
                        combined_file_folder_attr = {**file_attr, **folder_attr}
                        add_attributes_to_objects(customer_vid_objects, combined_file_folder_attr)

    return customer_vid_objects

# -------- Public Functions --------

# -------- Main --------

def main():
    #generic_ckl_processor(template_path+'\\RHEL8_V1R14.ckl')
    #customer_folder_attribute(template_path+'\\RHEL8_V1R14.ckl')
    #identify_new_ckl_files(s3_directory)

    print(finalize_objects())
    #objects = finalize_objects()
    #print(len(objects))

if __name__ == '__main__':
    
    main()

    #TODO: SO CLOSE!!! IT'S PRINTING A CRAP TON OF DATA FOR SOME REASON. PROBABLY THE CKLCLEANER. THINK ABOUT WHETHER OR NOT
    # TO CREATE A NEW TEMP CKL OR NOT - LOOK INTO THIS 10/25/24