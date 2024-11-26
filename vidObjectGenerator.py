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
import psycopg2
import glob
import datetime

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

def customer_ckl_processor(customer_ckl, date_switch):

    #Check if the file exists
    if not os.path.exists(customer_ckl):
        return None

    try: 
        #CULPRIT
        #customer_ckl = cleanMe(customer_ckl)

        if customer_ckl is not None:
            
            file_attributes = customer_file_attribute(customer_ckl)
            folder_attributes = customer_folder_attribute(customer_ckl)

            if file_attributes is None:
                return

            if date_switch and (file_attributes['date'] > time.strftime("%Y%m%d", time.gmtime(time.time() - 60*60*24*60))):
                root = etree.parse(customer_ckl).getroot()
                #root = etree.fromstring(customer_ckl)

                customer_vuln_objects = []

                for customer_vuln in root.xpath('.//VULN'):
                    customer_vuln_obj = customerVulnID()

                    #grabbing host ip and name if it exists
                    host_ip_element = root.find('.//HOST_IP')
                    host_name_element = root.find('.//HOST_NAME')

                    if host_ip_element is not None:
                        setattr(customer_vuln_obj, 'host_ip', host_ip_element.text)
                    else:
                        setattr(customer_vuln_obj, 'host_ip', None)

                    if host_name_element is not None:
                        setattr(customer_vuln_obj, 'host_name', host_name_element.text)
                    else:
                        setattr(customer_vuln_obj, 'host_name', None)

                    #need to add folder and file attributes

                    #file attributes
                    setattr(customer_vuln_obj, 'filename', file_attributes['filename'])
                    setattr(customer_vuln_obj, 'date', file_attributes['date'])
                    setattr(customer_vuln_obj, 'hash', file_attributes['hash'])
                    setattr(customer_vuln_obj, 'initials', file_attributes['initials'])

                    #folder attributes
                    #setattr(customer_vuln_obj, 'customer_name', folder_attributes['organization'])
                    setattr(customer_vuln_obj, 'customer_system', folder_attributes['system'])
                    setattr(customer_vuln_obj, 'customer_site', folder_attributes['site'])
                    setattr(customer_vuln_obj, 'system_version', folder_attributes['system_version'])
                    setattr(customer_vuln_obj, 'quarterly_audit', folder_attributes['quarterly_audit'])  

                    for stig_data in customer_vuln.xpath('./STIG_DATA'):
                        vuln_attribute = stig_data.find('VULN_ATTRIBUTE').text
                        attribute_data = stig_data.find('ATTRIBUTE_DATA').text
                        if hasattr(customer_vuln_obj, vuln_attribute.lower()):
                            setattr(customer_vuln_obj, vuln_attribute.lower(), attribute_data)   

                    customer_vuln_objects.append(customer_vuln_obj)
                return customer_vuln_objects
            
            if not date_switch:
                root = etree.parse(customer_ckl).getroot()
                #root = etree.fromstring(customer_ckl)

                if file_attributes is None:
                    return

                customer_vuln_objects = []

                for customer_vuln in root.xpath('.//VULN'):
                    customer_vuln_obj = customerVulnID()

                    #grabbing host ip and name if it exists
                    host_ip_element = root.find('.//HOST_IP')
                    host_name_element = root.find('.//HOST_NAME')

                    if host_ip_element is not None:
                        setattr(customer_vuln_obj, 'host_ip', host_ip_element.text)
                    else:
                        setattr(customer_vuln_obj, 'host_ip', None)

                    if host_name_element is not None:
                        setattr(customer_vuln_obj, 'host_name', host_name_element.text)
                    else:
                        setattr(customer_vuln_obj, 'host_name', None)


                    #need to add folder and file attributes

                    #file attributes
                    setattr(customer_vuln_obj, 'filename', file_attributes['filename'])
                    setattr(customer_vuln_obj, 'date', file_attributes['date'])
                    setattr(customer_vuln_obj, 'hash', file_attributes['hash'])
                    setattr(customer_vuln_obj, 'initials', file_attributes['initials'])

                    #folder attributes
                    #setattr(customer_vuln_obj, 'customer_name', folder_attributes['organization'])
                    setattr(customer_vuln_obj, 'customer_system', folder_attributes['system'])
                    setattr(customer_vuln_obj, 'customer_site', folder_attributes['site'])
                    setattr(customer_vuln_obj, 'system_version', folder_attributes['system_version'])
                    setattr(customer_vuln_obj, 'quarterly_audit', folder_attributes['quarterly_audit'])  

                    # Define a mapping of XML tags to object attributes
                    tag_to_attr = {
                        'FINDING_DETAILS': 'finding_details',
                        'STATUS': 'status',
                        'COMMENTS': 'comments',
                        'SEVERITY_OVERRIDE': 'severity_override',
                        'SEVERITY_JUSTIFICATION': 'severity_justification'
                    }

                    # Process STIG_DATA elements
                    for stig_data in customer_vuln.xpath('./STIG_DATA'):
                        vuln_attribute = stig_data.find('VULN_ATTRIBUTE').text
                        attribute_data = stig_data.find('ATTRIBUTE_DATA').text
                        if hasattr(customer_vuln_obj, vuln_attribute.lower()):
                            setattr(customer_vuln_obj, vuln_attribute.lower(), attribute_data)

                    # Process other elements based on the tag_to_attr mapping
                    for tag, attr in tag_to_attr.items():
                        element = customer_vuln.find(f'.//{tag}')
                        if element is not None and element.text:
                            setattr(customer_vuln_obj, attr, element.text)

                    customer_vuln_objects.append(customer_vuln_obj)
                return customer_vuln_objects
        return    
    except (etree.XMLSyntaxError, UnicodeDecodeError) as e:
        #print(f"Error parsing {customer_ckl}: {e}")
        return None

##FUNCTION: STEP THROUGH THE PULLED S3 DIRECTORY AND RETURN RESPECTIVE CUSTOMER ATTRIBUTES BASED ON LOCATION
##PARAMETER: THE CKL FILE (customer_ckl) PATH

#TODO

def customer_folder_attribute(customer_ckl):

    regexes = {
        #"organization" : r"^(DoD|CIV_LEA|Motorola|State&Local)$",
        "system": r"^(Army|DLA|Navy|USAF|USMC|BEP_TIGTA|Boeing_NRO|CBP|CDC|Coast Guard|Coast_Guard|CRSU|DoE|DOJ USMS|DOS WARN|FBI|FEMA|ICE|NASA Goddard Space Flight Center|NASA Marshall|NIH|NPS|OPC1|OSC Donovan|PANTEX|Raytheon|Senate_JAWS|TVA|US_Capitol_Police|USMS)",
        "site": r"^(DAF_ELMR.*|E2LMR|Fort |Camp |ACE)",
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
                initials = "XX"

            with open(path, 'rb') as f:
                bytes = f.read()
                readable_hash = hashlib.sha256(bytes).hexdigest()

            if not all([ckl, date, initials, readable_hash]):
                return
            
            return dict(filename=ckl, date=date, initials=initials, hash=readable_hash)
                
    return

## FUNCTION: ADDS ATTRIBUTES TO EXISTING OBJECTS
## PARAMETER: LIST OF EXISTING OBJECTS, DICTIONARY OF ATTRIBUTES TO ADD

def add_attributes_to_objects(objects, attributes):
    for obj in objects:
        for attr, value in attributes.items():
            setattr(obj, attr, value)


## FUNCTION: PULL EVERYTHING TOGETHER AND FINALIZE OBJECTS
## PARAMETER: NONE

def finalize_objects(date_switch):

    customer_vid_object_list = []

    conn = psycopg2.connect(
            dbname='ckl',
            user='postgresql',
            password='Batw1ngs-Adm1n1!',
            host='10.1.233.200',
            port='5432'
        )
    cur = conn.cursor()

    cur.execute("SELECT unique_key, hidden_file_path FROM pointer_paths WHERE date > current_date - interval '365 days';")
    rows = cur.fetchall()

    for unique_key, hidden_file_path in rows:
        directory = os.path.normpath(os.path.dirname(hidden_file_path))
        
        #check if the file path exists
        if os.path.exists(directory):
            search_pattern = os.path.join(directory, '*.ckl')
            ckls = glob.glob(search_pattern)

            if ckls:
                for ckl in ckls:
                    next_customer_vid_objects = customer_ckl_processor(ckl, date_switch)
                    if next_customer_vid_objects is not None:
                        customer_vid_object_list = customer_vid_object_list + next_customer_vid_objects

    return customer_vid_object_list

## FUNCTION: GENERATES A CREATE TABLE QUERY FOR A GIVEN TABLE NAME
## PARAMETER: THE NAME OF THE TABLE

def create_table_query_generator(table_name):
    create_table_query = f"""
        CREATE TABLE IF NOT EXISTS "{table_name}" (
                vuln_num VARCHAR(255),
                date DATE,
                filename VARCHAR(255),
                hash VARCHAR(255),
                customer_system VARCHAR(255),
                customer_site VARCHAR(255),
                system_version VARCHAR(255),
                quarterly_audit VARCHAR(255),
                status VARCHAR(255),
                finding_details TEXT,
                comments TEXT,
                host_name VARCHAR(255),
                host_ip VARCHAR(255),
                initials VARCHAR(255),
                rule_ver TEXT,
                severity VARCHAR(255),
                group_title TEXT,
                rule_id TEXT,
                rule_title TEXT,
                vuln_discuss TEXT,
                ia_controls TEXT,
                check_content TEXT,
                fix_text TEXT,
                false_positives TEXT,
                false_negatives TEXT,
                documentable BOOLEAN,
                mitigations TEXT,
                potential_impact TEXT,
                third_party_tools TEXT,
                mitigation_control TEXT,
                responsibility TEXT,
                security_override_guidance TEXT,
                check_content_ref TEXT,
                classification TEXT,
                stig_ref TEXT,
                targetkey TEXT,
                stig_uuid TEXT,
                legacy_id TEXT,
                cci_ref TEXT,
                severity_override TEXT,
                severity_justification TEXT,
                PRIMARY KEY (vuln_num, date, filename, hash)
            )
            """
    return create_table_query
# -------- Public Functions --------

# -------- Main --------

def main():
    #generic_ckl_processor(template_path+'\\RHEL8_V1R14.ckl')
    #customer_folder_attribute(template_path+'\\RHEL8_V1R14.ckl')
    #identify_new_ckl_files(s3_directory)

    date_switch = False #THIS WILL BE CHANGED TO REFLECT IF WE WANT TO PULL THE LAST 60 DAYS OF CKLs OR NOT. FALSE TO PULL EVERYTHING.

    vuln_objects = finalize_objects(date_switch)

    conn = psycopg2.connect(
            dbname='ckl',
            user='postgresql',
            password='Batw1ngs-Adm1n1!',
            host='10.1.233.200',
            port='5432'
        )
    
    cur = conn.cursor()

    # Create the meat table
    cur.execute(create_table_query_generator("house_of_meat"))

    # Initialize a set to store unique combinations of customer attributes
    unique_combinations = set()

    # Add the unique combinations to the set and also shove these in the meat table
    for obj in vuln_objects:
        combination = (obj.customer_system, obj.customer_site, obj.quarterly_audit)
        unique_combinations.add(combination)

    # Create audit-specific staging tables
    for combination in unique_combinations:
        table_name = f"{combination[0]}_{combination[1]}_{combination[2]}_staging"
        create_table_query = create_table_query_generator(table_name)
        cur.execute(create_table_query)

    # Commit the table creation
    conn.commit()

    # Collect all rows to be inserted for each table
    rows_to_insert = {}

    for obj in vuln_objects:
        table_name = f"{obj.customer_system}_{obj.customer_site}_{obj.quarterly_audit}_staging"
        # Extract the attribute names
        attributes = [attr for attr in dir(obj) if not attr.startswith('__') and not callable(getattr(obj, attr))]

        # Extract the attribute values
        attribute_values = [getattr(obj, attr) for attr in attributes]

        if table_name not in rows_to_insert:
            rows_to_insert[table_name] = []

        rows_to_insert[table_name].append(attribute_values)

    # Insert rows in batches
    for table_name, rows in rows_to_insert.items():
        # Generate the columns and values strings
        columns = ', '.join(attributes)
        values_placeholder = ', '.join(['%s'] * len(attributes))

        # Create the insert query
        insert_query = f'INSERT INTO "{table_name}" ({columns}) VALUES ({values_placeholder})'

        # Execute the batch insert
        cur.executemany(insert_query, rows)

    # Commit the transaction
    conn.commit()

    # Commit the transaction and close the connection
    conn.commit()
    cur.close()
    conn.close()

if __name__ == '__main__':
    
    print(f"Start time: {datetime.datetime.now()}")
    main()
    print(f"End time: {datetime.datetime.now()}")
