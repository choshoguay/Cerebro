import os
import re

def cleanMe(ckl):
    
    if os.path.basename(ckl).startswith("."):
        return
    
    # Correct regex pattern to match invalid XML characters
    invalid_xml_chars = re.compile(r'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]')
    data = None
    encodings = ['utf-8']
    
    for encoding in encodings:
        try: 
            with open(ckl, 'r', encoding=encoding) as f:
                data = f.read()
                break
        except UnicodeDecodeError:
            continue
    
    if data is None:
        return
    
    # Remove invalid XML characters and assign the result back to data
    data = invalid_xml_chars.sub('', data)
    
    return data