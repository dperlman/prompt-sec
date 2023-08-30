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

sublist_schema = {'Modes_Of_Introduction':{'subkey':'Introduction', 'useitems':['Phase', 'Note']},
                  'Potential_Mitigations':{'subkey':'Mitigation', 'useitems':['Phase', 'Description']}, 
                  'Common_Consequences':{'subkey':'Consequence', 'useitems':['Scope', 'Impact', 'Note']}, 
                  'Detection_Methods':{'subkey':'Detection_Method', 'useitems':['Method', 'Description', 'Effectiveness_Notes']},
                  'Related_Attack_Patterns':{'subkey':'Related_Attack_Pattern', 'useitems':['@CAPEC_ID']},
                  'Related_Weaknesses':{'subkey':'Related_Weakness', 'useitems':["@Nature", "@CWE_ID"]},
                  'Observed_Examples':{'subkey':'Observed_Example', 'useitems':['Reference', 'Description']}, 
                  'Alternate_Terms':{'subkey':'Alternate_Term', 'useitems':['Term', 'Description']},
                  } # leaving out ones I already decided not to do, also leaving out ones that need a different kind of processing

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
            out = json.load(infile)
    else: 
        print('Simplifying cwe data, loading %s' % fname)
        with open(fname, 'r') as infile:
            cwe = json.load(infile)
        out = {}
        #testsucc = 0
        #testfail = 0
        for i in tqdm(cwe.keys()):
            #s, f = test_cwe_item(cwe[i])
            #testsucc += s
            #testfail += f
            #continue
            v = simplify_cwe_item(cwe[i])
            if not v: continue
            if len(v.keys()) == 0: continue
            out[i] = v
        #print(f'successes: {testsucc} failures: {testfail}')
        #sys.exit()
        with open(outfname, 'w') as outfile:
            json.dump(out, outfile, indent=2)
    return out
    

def test_cwe_item(cwe):
    if "Related_Weaknesses" in cwe:
        if list(cwe["Related_Weaknesses"].keys())[0] == "Related_Weakness":
            return 1,0
        else:
            return 0,1
    else:
        return 0,0
    

def simplify_cwe_item(cwe):
    out = {}
    for k in cwe.keys():
        kk = k.lstrip('@')
        if kk in ["ID", "Name", "Description", "Extended_Description"]:
            out[kk] = subl(cwe[k])
        elif kk in ["Weakness_Ordinalities", "Common_Consequences", "Taxonomy_Mappings", "References", "Mapping_Notes", "Content_History",
                    "Affected_Resources", "Likelihood_Of_Exploit", "Abstraction", "Structure", "Status", "Functional_Areas", "Notes",
                    "Related_Weaknesses"]:
            continue
        elif kk == "Related_Weaknesses":
            outitem = parse_related_weaknesses(cwe["Related_Weaknesses"])
            if outitem: out[kk] = outitem
        elif kk == "Applicable_Platforms":
            outitem = parse_applicable_platforms(cwe["Applicable_Platforms"])
            if outitem: out[kk] = outitem
        elif kk == "Potential_Mitigations":
            outitem = parse_potential_mitigations(cwe["Potential_Mitigations"])
            if outitem: out[kk] = outitem
        elif kk == "Demonstrative_Examples":
            outitem = parse_demonstrative_examples(cwe["Demonstrative_Examples"])
            if outitem: out[kk] = outitem
        elif kk == "Detection_Methods":
            outitem = parse_detection_methods(cwe["Detection_Methods"])
            if outitem: out[kk] = outitem
        elif kk == "Observed_Examples":
            outitem = parse_observed_examples(cwe["Observed_Examples"])
            if outitem: out[kk] = outitem
        elif kk == "Alternate_Terms":
            outitem = parse_alternate_terms(cwe["Alternate_Terms"])
            if outitem: out[kk] = outitem
        elif kk == "Related_Attack_Patterns":
            outitem = parse_related_attack_patterns(cwe["Related_Attack_Patterns"])
            if outitem: out[kk] = outitem
        elif kk == "Background_Details":
            outitem = parse_background_details(cwe["Background_Details"])
            if outitem: out[kk] = outitem
        elif kk == "Modes_Of_Introduction":
            outitem = parse_modes_of_introduction(cwe["Modes_Of_Introduction"])
            if outitem: out[kk] = outitem
        else:
            print("unknown cwe item: %s" % kk)
    return out


def subl(subitem):
    # used at the lowest level of parsing some items like Language
    # subroutine for parse_applicable_platforms and maybe others
    if isinstance(subitem, list):
        if (len(subitem[0])) <= 20 and not ((len(subitem) > 1) and len(subitem[1]) > 20):
            return ', '.join(filter(None, [subl(i) for i in subitem]))
        else:
            return '\n'.join(filter(None, [subl(i) for i in subitem]))
    elif isinstance(subitem, dict):
        if "@Name" in subitem:
            return subl(subitem["@Name"])
        elif ("@Class" in subitem) and subitem["@Class"][0:4] != "Not ":
            return subl(subitem["@Class"])
        elif "xhtml:p" in subitem:
            return subl(subitem["xhtml:p"])
        else:
            #print('subl found no name or class (or nonspecific class) for %s' % subitem.keys())
            return ''
    elif isinstance(subitem, str):
        return subitem
        
def sublist(subitem, key):
    if key in sublist_schema:
        kinfo = sublist_schema[key]
        subkey = kinfo['subkey']
        useitems = kinfo['useitems']
        subitem = subitem[subkey]
        if hasattr(subitem, 'keys'): # it's a dictionary
            if (useitems[0] in subitem.keys()) and ((len(useitems)==1) or (useitems[1] in subitem.keys())):
                return subdict(subitem, useitems)
            else:
                return None
        elif hasattr(subitem, 'append'): # it's a list
            #print(subitem)
            outlist = [subdict(i, useitems) for i in subitem]
            #print(outlist)
            return '\n\n'.join(outlist)
        else:
            return None
    else:
        return None

def subdict(subitem, useitems):
    if useitems[0] in subitem:
        outstr = subl(subitem[useitems[0]]) + ': '
    else:
        outstr = ''
    #print('Initial outstr: %s' % outstr)
    if len(useitems) == 1: return outstr
    if (len(useitems)) > 1 and useitems[1] in subitem:
        #print(useitems[1])
        #print(subitem[useitems[1]])
        outstr += subl(subitem[useitems[1]])
        #print('Extended outstr: %s' % outstr)
    if len(useitems) == 2: return outstr
    outlist = [outstr] + [subitem[i] for i in useitems[2:] if (i in subitem)]
    outstr = '\n'.join(outlist)
    return outstr # note: what's missing here is if there are html tags or sub-sublists or whatever ############


def parse_related_weaknesses(item):
    # this one is pretty simple
    return item["Related_Weakness"]

def parse_applicable_platforms(item):
    # could be Language, Operating_System, Architecture, Technology
    out = {}
    for i in item.keys():
        if i in ["Language", "Operating_System", "Architecture", "Technology"]: # any others? I don't think any that matter
            outitem = subl(item[i])
            if outitem: out[i] = outitem
        else:
            print("unknown Applicable Platform item: %s" % i)
    return out


def parse_potential_mitigations(item):
    return sublist(item, 'Potential_Mitigations')

def parse_demonstrative_examples(item):
    return sublist(item, 'Demonstrative_Examples')

def parse_detection_methods(item):
    return sublist(item, 'Detection_Methods')

def parse_observed_examples(item):
    return sublist(item, 'Observed_Examples')

def parse_alternate_terms(item):
    return sublist(item, 'Alternate_Terms')

def parse_related_attack_patterns(item):
    return sublist(item, 'Related_Attack_Patterns')

def parse_background_details(item):
    # this one needs to be done specifically. in a way that uses subl() because it has xhtml tags in it.
    return subl(item)

def parse_modes_of_introduction(item):
    return sublist(item, 'Modes_Of_Introduction')

def chunk_yaml_list(input, name, size=2000):
    if hasattr(input, 'keys'):
        # turn the dict into a list
        input = [input[i] for i in input.keys()]
    fname = '%s_ychunk_size_%s.json' % (name, size)
    #input = input[0:500]
    if os.path.isfile(fname):
        print('reading already chunked yaml %s of size %d' % (fname, size))
        with open(fname, 'r') as infile:
            out = json.load(infile)
    else:
        out = []
        outItem = ''
        outItemLen = 0
        print('chunking yaml output %s to size %d' % (fname, size))
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
        #print(out[2])
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
    print("number of cwes: %d" % len(cwe))
    chunksize = 1 # just do each one individually
    chunkList = chunk_yaml_list(cwe, 'cwe', size=chunksize)
    print("Number of chunks: %d" % len(chunkList))
    # that works. now try the model
    cwe_embedding = embed_text_list(chunkList)
    with open('cwe_embedding.json', 'w') as outfile:
        json.dump(cwe_embedding, outfile, indent=2)

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
