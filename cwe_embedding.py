import openai
import json
import textwrap
import xml.etree.ElementTree as ET
import sys
import re
from tqdm import tqdm
import numpy as np
import pandas as pd
import os.path
import yaml
import xmltodict
import time
from time import time, sleep
from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
    retry_if_not_exception_type
)  # for exponential backoff


def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()


openai.api_key = open_file('openaiapikey_leviathan.txt')
#openai.api_key = open_file('openaiapikey_stanford.txt')


def retryCallback(retry_state):
    print(retry_state.outcome)
    return 'EMBED_FAIL'

@retry(wait=wait_random_exponential(min=3, max=120), 
       stop=stop_after_attempt(6), 
       retry=retry_if_not_exception_type(openai.error.InvalidRequestError),
       retry_error_callback=retryCallback)
def gpt3_embedding(content, model='text-embedding-ada-002'):
    # V2 embeddings can have 8191 tokens in input
    try:
        response = openai.Embedding.create(input=content, model=model)
    except openai.error.InvalidRequestError:
        return 'invalidRequest'
    vector = response['data'][0]['embedding']  # this is a normal list
    return vector

def load_cwe():
    fname = 'cVWPeData/cwec_v4.12.xml'
    outfname = 'cVWPeData/cwe.json'
    if os.path.isfile(outfname):
        print('JSON cwe data exists, loading %s' % outfname)
        with open(outfname, 'r') as infile:
            data = json.load(infile)
    else: 
        print('Converting CWE data from XML to JSON, loading %s' % fname)
        with open(fname, 'r') as infile:
            data = xmltodict.parse(infile.read())["Weakness_Catalog"]["Weaknesses"]["Weakness"]
            outdata = {}
            for i in data:
                outdata[i["@ID"]] = i
        with open(outfname, 'w') as outfile:
            json.dump(outdata, outfile, indent=2)
    return data

def simplify_cwe():
    fname = 'cVWPeData/cwe.json'
    outfname = 'cVWPeData/cwe_simple.json'
    if os.path.isfile(outfname):
        print('Simplified cwe data exists, loading %s' % outfname)
        with open(outfname, 'r') as infile:
            data = json.load(infile)
    else: 
        print('Simplifying cwe data, loading %s' % fname)
        with open(fname, 'r') as infile:
            cwe = json.load(infile)
        out = {}
        for i in tqdm(cwe.keys()):
            v = simplify_cwe_item(cwe[i])
            if not v: continue
            if len(v.keys()) == 0: continue
            out[i] = v
        with open(outfname, 'w') as outfile:
            json.dump(out, outfile, indent=2)
    return out
    

def simplify_cwe_item(cwe):
    out = {}
    for k in cwe.keys():
        kk = k.lstrip('@')
        if kk in ["ID", "Name", "Description", "Extended_Description"]:
            out[kk] = cwe[k]
        elif kk in ["Weakness_Ordinalities", "Common_Consequences", "Taxonomy_Mappings", "References", "Mapping_Notes", "Content_History"]:
            continue
        elif kk == "Related_Weaknesses":
            out[kk] = parse_related_weaknesses(cwe["Related_Weaknesses"])
        elif kk == "Applicable_Platforms":
            out[kk] = parse_applicable_platforms(cwe["Applicable_Platforms"])
        elif kk == "Potential_Mitigations":
            out[kk] = parse_potential_mitigations(cwe["Potential_Mitigations"])
        elif kk == "Demonstrative_Examples":
            out[kk] = parse_demonstrative_examples(cwe["Demonstrative_Examples"])
        else:
            print("unknown cwe item: %s" % kk)
    return out


def parse_related_weaknesses(item):
    # this one is pretty simple
    return item["Related_Weakness"]

def subl(subitem):
    # used at the lowest level of parsing some items like Language
    # subroutine for parse_applicable_platforms and maybe others
    if isinstance(subitem, list):
        return ', '.join(subl(i) for i in subitem)
    elif isinstance(subitem, dict):
        if "@Name" in subitem:
            return subitem["@Name"]
        elif ("@Class" in subitem) and subitem["@Class"][0:4] != "Not ":
            return subitem["@Class"]
        else:
            print('subl found no name or class (or nonspecific class) for %s' % subitem.keys())
            return ''
        
def parse_applicable_platforms(item):
    # could be Language, Operating_System, Architecture, Technology
    out = {}
    for i in item.keys():
        if i in ["Language", "Operating_System", "Architecture", "Technology"]: # any others? I don't think any that matter
            out[i] = subl(item[i])
        else:
            print("unknown Applicable Platform item: %s" % i)
    return out


def parse_potential_mitigations(item):
    return None

def parse_demonstrative_examples(item):
    return None

def chunk_yaml_list(input, name, size=2000):
    fname = '%s_yaml_chunks_size_%s.json' % (name, size)
    #input = input[0:500]
    if os.path.isfile(fname):
        print('reading already chunked yaml of size %d' % size)
        with open(fname, 'r') as infile:
            out = json.load(infile)
    else:
        out = []
        outItem = ''
        outItemLen = 0
        print('chunking yaml output to size %d' % size)
        for i in tqdm(input):
            y = yaml.safe_dump(i, sort_keys=False, width=size)
            l = len(y)
            #print(l)
            if outItemLen + l + 2 > size:
                out.append(outItem)
                outItem = y
                outItemLen = l
            else:
                outItem += ('\n\n' + y)
                outItemLen += (2 + l)
        with open(fname, 'w') as outfile:
            json.dump(out, outfile, indent=2)
    return out


def embed_text_list(l):
    out = []
    #l = l[0:3]
    n = 0
    for i in tqdm(l):
        embedding = gpt3_embedding(i.encode(encoding='ASCII',errors='ignore').decode())
        if embedding == 'EMBED_FAIL':
            print('embed fail for item number %d of %d' % (n, len(l)))
            time.sleep(300)
        info = {'content': i, 'vector': embedding}
        #print(f_vect(embedding), '\n\n\n')
        out.append(info)
        n += 1
    return out

def f_vect(v):
    return ', '.join('%0.3f' % x for x in v)


if __name__ == '__main__':
    # first do this if it needs to be done
    load_cwe()
    cwe = simplify_cwe()
    # now we have cwe, one way or another
    # need to break into max 8192 token chunks
    chunksize = 2000
    chunkList = chunk_yaml_list(nvdcve, 'nvdcve', size=chunksize)
    print("Number of chunks: %d" % len(chunkList))
    # that works. now try the model
    nvdcve_embedding = embed_text_list(chunkList)
    with open('nvdcve_embedding_%d.json' % chunksize, 'w') as outfile:
        json.dump(nvdcve_embedding, outfile, indent=2)

    sys.exit()


    ########## OK GREAT!!!
    # I did nvdcve
    # now run the AI thing on it
    # in order to make 


    # Then after that,
    # do CWE and then CPE
    #alltext = open_file('nvdcvecwecpedata/allitems.xml')
    #tree = ET.parse('nvdcvecwecpedata/cwec_v4.12.xml') 
    #root = tree.getroot()
