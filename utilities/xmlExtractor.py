### @author: David Wong
### @date: 09/04/2024
### 
### Description: Basic script to extract XML files from an ISO file. Auto identifies the ISO file that contains the schema of Q# Audit Disk ####
### and extracts the XML files to the Public Downloads STIGs directory.


# -------- External Modules --------
import zipfile, os, shutil, win32api, re
from tqdm import tqdm

# -------- Global Variables --------
public_downloads = 'C:/Users/Public/Downloads'
stig_path = 'C:/Users/Public/Downloads/STIGs'

# -------- Private Functions --------

## FUNCTION: EXTRACT .XML FILES FROM ISO.
## PARAMETERS: THE PATH TO THE ISO (iso_path).
def clean_extract_xml_from_iso(iso_path):

    #grabs the total number of .zip files to track the progress of the extraction.
    total = sum([len(files) for r, d, files in os.walk(iso_path) if any(f.endswith('.zip') for f in files)])

    try:
        print(f"Cleaning up {stig_path}.")
        shutil.rmtree(stig_path, ignore_errors=True)
    except PermissionError:
        print(f"Unable to clean files from {stig_path}. Please close any open files and try again.")
        return
    print(f"Extracting XML files from ISO - {iso_path}")

    with tqdm(total=total, desc='Extracting XML Files') as pbar:
        for root, dirs, files in os.walk(iso_path):
            for file in files:
                if file.endswith('.zip'):
                    zip_path = os.path.join(root, file)
                    relative_dir = os.path.relpath(zip_path, iso_path)
                    extract_to = os.path.join(stig_path, relative_dir)
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        for filename in zip_ref.namelist():
                            if filename.endswith('.xml'):
                                try:
                                    os.makedirs(extract_to, exist_ok=True)
                                    zip_ref.extract(filename, extract_to)
                                except FileExistsError:
                                    print(f"{filename} already exists in {extract_to}. Skipping extraction.")
                    pbar.update()
    print('Extraction complete.')

## FUNCTION: FIND THE DRIVE LETTER OF THE ISO THAT THAT SCHEMA OF Q# Audit Disk ####
## PARAMETER: NONE
def find_iso_drive():
    drive_letters = win32api.GetLogicalDriveStrings().split('\000')[:-1]
    for drive_letter in drive_letters:
        try:
            volume_name = win32api.GetVolumeInformation(drive_letter)[0]
            if re.match(r'Q\d Audit Disk \d{4}', volume_name):
                return drive_letter
        except win32api.error:
            pass
    return None

# -------- Public Functions --------

## FUNCTION: MAIN METHOD TO CALL PRIVATE FUNCTIONS TO EXTRACT XML FILES FROM ISO.
## PARAMETERS: NONE

def main():
    iso_path = find_iso_drive()
    if iso_path is None:
        print('Unable to find the ISO drive.')
        return
    clean_extract_xml_from_iso(iso_path)

## MAIN METHOD

if __name__ == '__main__':
    main()