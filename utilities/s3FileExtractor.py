### @author: David Wong
### @date: 09/04/2024
### Description: Script that unzips and takes in all of the CKLs and also 

# -------- External Modules --------

import sys
import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
import zipfile
import re
import shutil
from itertools import tee

# -------- External Classes --------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from classes import fileAttributesClass as fileAttributeClass

# -------- Global Variables --------

#s3 = '\\\\10.38.97.45\\ci475316-fed-s3-storage-share\\customers #use this at the end 
s3 = 'E:\\Customers' ##for testing

organization = {
    'CIV_LEA': ['NA'],
    'DoD': ['Army', 'DLA', 'Navy', 'USAF', 'USMC']
    }   

postgres_db = '10.1.233.199'

destination_path = 'C:/Users/Public/Downloads/New_CKLs/'

date_patterns = [ #ORDER HERE MATTERS - IT SHOULD MATCH AGAINST THE LONGEST DATE FORMAT FIRST
    
    (r'(?<=\D)(\d{8})(?=\D)', '%Y%m%d'),  # 20211228
    (r'(?<=\D)(\d{8})(?=\D)', '%d%m%Y'),  # 28122021
    (r'(?<=\D)(\d{8})(?=\D)', '%m%d%Y'),  # 12282021
    (r'(?<=\D)(\d{6})(?=\D)', '%y%m%d'),  # 211228
    (r'(?<=\D)(\d{2}\d{2}\d{4})(?=\D)', '%m%d%Y'),  # 01012022
    (r'(?<=\D)(\d{2}\d{2}\d{2})(?=\D)', '%m%d%y'),  # 010122
    (r'(?<=\D)(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{4})(?=\D)', '%d%b%Y'),  # 28Jan2022
    (r'(?<=\D)(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2})(?=\D)', '%d%b%y'),  # 28Jan22
    (r'(?<=\D)(\d{4}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2})(?=\D)', '%Y%b%d'),  # 2022Jan28
    (r'(?<=\D)(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2})(?=\D)', '%y%b%d'),  # 22Jan28

]

# -------- Private Functions --------

## FUNCTION : GET THE AGE OF THE FILE BASED ON THE NAMING IN THE FILE I.E. AUDIT_10JAN21_INITIALS.CKL
## PARAMETER : FILE NAME

def get_file_age(filepath):
    filename = os.path.basename(filepath)
    for pattern, date_format in date_patterns:
        match = re.search(pattern, filename)
        if match:
            date_str = match.group(1)
            try:
                date = datetime.strptime(date_str, date_format)
                age = (datetime.now() - date).days
                return filename, age
            except ValueError:
                continue


## FUNCTION : GRAB THE S3 DIRECTORY PATH TO FILES AND THEN EXTRACT 
## PARAMETER : TAKES IN LIST OF ZIP FILES AND THE DESTINATION TO EXTRACT TO

def extract_files_from_s3(zips, raw_files, destination):
    
    error_files = []

    for zip_file in zips:
        directory = os.path.dirname(zip_file)
        constant_path = 'Customers\\'
        directory_parts = directory.split(constant_path)
        directory = constant_path + directory_parts[1]
        folder_structure = destination + directory
        if not os.path.exists(folder_structure):
            try:
                print(f'Creating {folder_structure}...')
                os.makedirs(folder_structure, exist_ok=True)
            except PermissionError:
                print(f"Unable to create {folder_structure}. Please close any open files and try again.")
                return
        else:
            pass
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:       
            print(f'Extracting {zip_file} to {folder_structure}')
            try:
                zip_ref.extractall(folder_structure)
            except FileNotFoundError as e:
                error_files.append(folder_structure)
                print(f"Unable to extract files to {folder_structure}. Error {e}. Please check the path and try again.")
                continue

    for files in raw_files:
        directory = os.path.dirname(files)
        constant_path = 'Customers\\'
        directory_parts = directory.split(constant_path)
        directory = constant_path + directory_parts[1]
        folder_structure = destination + directory
        if not os.path.exists(folder_structure):
            try:
                print(f'Creating {folder_structure}...')
                os.makedirs(folder_structure, exist_ok=True)
            except PermissionError:
                print(f"Unable to create {folder_structure}. Please close any open files and try again.")
                return
        else:
            pass
        try:
            shutil.copy(files, folder_structure)
        except FileNotFoundError as e:
            error_files.append(files)
            print(f"Unable to copy files to {folder_structure}. Error {e}. Please check the path and try again.")
            continue


## FUNCTION : SCAN S3 DIRECTORY FOR RESPECTIVE ZIP FILES THAT CONTAIN THE SCAN DATA
## PARAMETER : S3 DIRECTORY PATH

def getNewScans(directory):

    now = datetime.now()

    ## CHANGE ME TO 30 DAYS ##
    two_years_ago = now - relativedelta(day=730) #temporarily use 2 years for the initial run, then switch to 7 days 
    #30_days_ago = now - relativedelta(days=30)

    zip_files = []
    raw_ckls = []  
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            ##insert file object creation here
            ##maybe use this place to differentiate between files that exist within a database or whether it's new?
            file = os.path.join(dirpath, filename)
            
            #if it's a .zip file
            if filename.endswith('.zip') and filename.startswith('Deliverables'):
                if(two_years_ago < datetime.fromtimestamp(os.path.getctime(file))):
                    #print(f'Found zip {file}: Appending to zip list...')
                    zip_files.append(file)

            #if it's a raw ckl
            if filename.endswith('.ckl'):
                try:
                    if(two_years_ago < datetime.fromtimestamp(os.path.getctime(file))):
                        #print(f'Found {file}: Appending to file list...')
                        raw_ckls.append(file.replace("/", "\\"))
                except FileNotFoundError as e:
                    print(f"Error: {e}")
                    continue

    return zip_files, raw_ckls

# -------- Public Functions --------

def main():

    #######
    print('Start Time: ', datetime.now().strftime("%m/%d/%Y %H:%M:%S"))
    #######

    #------ MAIN METHOD ------

    #get both the list of zip files and raw ckl files.
    zip_list, raw_ckls = getNewScans(s3)

    #clean the raw_ckls list of files that are not valid (None) and if the age of the file is less than 7 days. 
    raw_ckls = [ckl for ckl in raw_ckls if get_file_age(ckl) is not None]

    #perform extraction of the identified zip files in s3 
    extract_files_from_s3(zip_list, raw_ckls, destination_path)

    #------ MAIN METHOD ------

    #######
    print('End Time: ', datetime.now().strftime("%m/%d/%Y %H:%M:%S"))
    #######


if __name__ == '__main__':
    main()



