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
    fname = 'nvdcvecwecpedata/cwec_v4.12.xml'
    outfname = 'nvdcvecwecpedata/cwe.json'
    if os.path.isfile(outfname):
        print('Loading %s' % outfname)
        with open(outfname, 'r') as infile:
            data = json.load(infile)
    else: 
        print('Loading %s' % fname)
        with open(fname, 'r') as infile:
            data = xmltodict.parse(infile.read())["Weakness_Catalog"]["Weaknesses"]["Weakness"]
            outdata = {}
            for i in data:
                outdata[i["@ID"]] = i
        with open(outfname, 'w') as outfile:
            json.dump(outdata, outfile, indent=2)
    return data

def parse_cwe(cwe):
    out = []
    print('Parsing data')
    impacts = 0
    noImpacts = 0
    for i in tqdm(nvdcve):
        proc = parse_nvdcve_item(i)
        if not proc: continue
        out.append(proc)
        if proc['severity'] == 'unknown':
            noImpacts += 1
        else:
            impacts += 1
    print('Total complete data: %d Missing impacts: %d' % (impacts, noImpacts))
    # 209412, missing: 503
    return out
    

def parse_nvdcve_item(cve):
    cveID = cve['cve']["CVE_data_meta"]["ID"]
    cwe = cve['cve']["problemtype"]["problemtype_data"][0]["description"]
    cwe = [i['value'] for i in cwe]
    description = cve['cve']["description"]["description_data"]
    description = '\n\n'.join([i['value'].replace('\n', ' ') for i in description])
    if description.startswith('** REJECT **'):
        return False;
    cpes = parse_nvdcve_configurations(cve["configurations"])
    # now do impact etc
    #print(cve)
    severity, exploitability, impact = parse_nvdcve_impacts(cve['impact'])
    if severity == 'unknown':
        print(cve)
    out = {'cve':cveID, 'cwes':cwe, 'cpes':cpes, 'severity':severity, 'exploitability':exploitability, 'impact':impact, 'description':description}
    return out


def parse_nvdcve_configurations(c):
    nodes = c['nodes']
    out = []
    for n in nodes:
        cpe23Uris = [i["cpe23Uri"] for i in n["cpe_match"]]
        cpes = [' '.join(i.split(':')[3:5]) for i in cpe23Uris]
        cpes = list(set(cpes)) # remove duplicates
        out.extend(cpes)
    return out

def parse_nvdcve_impacts(i):
    #print(i)
    if "baseMetricV2" in i:
        severity = i["baseMetricV2"]['severity']
        exploitability = float(i["baseMetricV2"]["exploitabilityScore"])/2
        impact = float(i["baseMetricV2"]["impactScore"])/2
    elif "baseMetricV3" in i:
        severity = i["baseMetricV3"]["cvssV3"]["baseSeverity"]
        exploitability = float(i["baseMetricV3"]["exploitabilityScore"])
        impact = float(i["baseMetricV3"]["impactScore"])
    else:
        print(i)
        severity = 'unknown'
        exploitability = 'unknown'
        impact = 'unknown'
    return severity, exploitability, impact

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
    cwefile = 'cwe.json'
    if os.path.isfile(cwefile):
        with open(cwefile, 'r') as infile:
            cwe = json.load(infile)
    else:
        cwe = parse_cwe(load_cwe())
        with open(cwefile, 'w') as outfile:
            json.dump(cwe, outfile, indent=2)
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
