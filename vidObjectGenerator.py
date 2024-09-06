### @author: David Wong
### @date: 09/04/2024
### Description: Script that creates V-ID objects from CKLs.


# -------- External Modules -------- 
import os
import xml.etree.ElementTree as ET
from lxml import etree
from bs4 import BeautifulSoup

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

##FUNCTION: STEP THROUGH THE S3 DIRECTORY AND RETURN RESPECTIVE CUSTOMER ATTRIBUTES BASED ON LOCATION
##PARAMETER: THE CKL FILE (customer_ckl)

#TODO

##FUNCTION: PROCESS INDIVIDUAL CUSTOMER CKL FILES AND RETURNS A LIST OF CUSTOMER VID OBJECTS
##PARAMETER: THE PATH TO THE CUSTOMER CKL FILE (customer_ckl)

def customer_ckl_processeor(customer_ckl):
    tree = etree.parse(customer_ckl)
    root = tree.getroot()

    customer_vuln_objects = []
    for customer_vuln in root.xpath('.//VULN'):
        customer_vuln_obj = customerVulnID()
        setattr(customer_vuln_obj, 'host_ip', tree.find('HOST_IP').text)

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
    generic_ckl_processor(template_path+'\\RHEL8_V1R14.ckl')

if __name__ == '__main__':
    main()