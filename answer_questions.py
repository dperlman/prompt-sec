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
import time
from time import time, sleep
import asyncio
from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
    retry_if_not_exception_type
)  # for exponential backoff

gpt_chat_params = \
    {'temperature':0.6,
    'max_tokens':2000,
    'top_p':1.0,
    'frequency_penalty':0.25,
    'presence_penalty':0.0,
    'stop':['<<END>>']
}

# TO DO
# Add full logging
# Improve prompts
# of course add CWE and CPE
# Finally add Leviathan data

def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()


#openai.api_key = open_file('openaiapikey_stanford.txt')
openai.api_key = open_file('openaiapikey_leviathan.txt')


def retryCallback(retry_state):
    print(retry_state.outcome)
    return 'GPT_FAIL'

@retry(wait=wait_random_exponential(min=3, max=120), 
       stop=stop_after_attempt(6), 
       retry=retry_if_not_exception_type(openai.error.InvalidRequestError),
       retry_error_callback=retryCallback)
def gpt3_embedding(content, engine='text-embedding-ada-002'):
    # V2 embeddings can have 8191 tokens in input
    try:
        response = openai.Embedding.create(input=content,engine=engine)
    except openai.error.InvalidRequestError:
        return 'invalidRequest'
    vector = response['data'][0]['embedding']  # this is a normal list
    #print(vector)
    return vector



def similarity(v1, v2):  # return dot product of two vectors
    if isinstance(v1, str) or isinstance(v2,str):
        return 0
    return np.dot(v1, v2)


def search_index(text, data, count=20):
    vector = gpt3_embedding(text)
    scores = list()
    print('calculating all embedding similarities...')
    for i in tqdm(data):
        score = similarity(vector, i['vector'])
        #print(score)
        scores.append({'content': i['content'], 'score': score})
    ordered = sorted(scores, key=lambda d: d['score'], reverse=True)
    return ordered[0:count]


# use either gpt-4-32k
# or gpt-3.5-turbo-16k
def gpt_completion(prompt, model='gpt-3.5-turbo-16k', temp=0.6, top_p=1.0, tokens=2000, freq_pen=0.25, pres_pen=0.0, stop=['<<END>>']):
    max_retry = 5
    retry = 0
    prompt = prompt.encode(encoding='ASCII',errors='ignore').decode()
    while True:
        try:
            response = openai.ChatCompletion.create(
                model=model,
                messages = [
                    {"role":"user", "content":prompt}
                ],
                temperature=temp,
                max_tokens=tokens,
                top_p=top_p,
                frequency_penalty=freq_pen,
                presence_penalty=pres_pen,
                stop=stop)
            #print(response)
            #text = response['choices'][0]['text'].strip()
            text = response['choices'][0]['message']['content'].strip()
            text = re.sub('\s+', ' ', text)
            filename = '%s_gpt3.txt' % time()
            with open('gpt3_logs/%s' % filename, 'w') as outfile:
                outfile.write('PROMPT:\n\n' + prompt + '\n\n==========\n\nRESPONSE:\n\n' + text)
            return text
        except Exception as oops:
            retry += 1
            if retry >= max_retry:
                return "GPT3 error: %s" % oops
            print('Error communicating with OpenAI:', oops)
            sleep(1)


def parse_template_prompt(template, query=None, passage=None, addl_passage=None):
   # build the messages structure for the API
    messages = []
    if 'SYSTEM' in template:
        messages = [{'role':'system', "content":template['SYSTEM']}]
    for item in template['PROMPTS']:
        if 'USER' in item:
            t = item['USER']
            if query:
                t = t.replace('<<QUERY>>', query)
            if passage:
                t = t.replace('<<PASSAGE>>', passage)
            if addl_passage:
                t = t.replace('<<ADDL_PASSAGE>>', addl_passage)
            # now add it
            messages.append({'role':'user', 'content':t})
        elif 'ASSISTANT' in item:
            messages.append({'role':'assistant', 'content':item['ASSISTANT']})
    return messages
 

# @retry(wait=wait_random_exponential(min=3, max=120), 
#        stop=stop_after_attempt(6), 
#        retry=retry_if_not_exception_type(openai.error.InvalidRequestError),
#        retry_error_callback=retryCallback)
async def gpt_completion_coro(prompt=None, messages=None, model='gpt-3.5-turbo-16k'):
    if messages:
        pass
    elif prompt:
        prompt = prompt.encode(encoding='ASCII',errors='ignore').decode()
        messages = [{"role":"user", "content":prompt}]
    else:
        # well if neither is provided, that's an error
        print('error: no prompt or messages given to gpt_completion_coro')
    print('Starting acreate for prompt %s' % prompt)
    response = await openai.ChatCompletion.acreate(
        model=model,
        messages = messages,
        **gpt_chat_params)
    #print(response)
    text = response['choices'][0]['message']['content'].strip()
    tokens = response['usage']['total_tokens']
    return {'text':text, 'tokens':tokens}

async def concurrent_gpt_completions(prompts=None, message_groups=None):
    #tasks = [asyncio.create_task(gpt_completion_coro(p)) for p in prompts]
    if prompts:
        tasks = [gpt_completion_coro(prompt=p) for p in prompts]
    elif message_groups:
        tasks = [gpt_completion_coro(messages=m) for m in message_groups]
    results = await asyncio.gather(*tasks)
    #print(results)
    return results



if __name__ == '__main__':
    #testprompts = ['Write a limerick with the word "blue" in it', 'Write a limerick with the word "green" in it', 'Write a limerick with the word "yellow" in it']
    #print(asyncio.run(concurrent_gpt_completions(prompts=testprompts)))
    #sys.exit()

    #embfile = 'nvdcve_embedding_2000.json'
    embfile = 'cwe_embedding.json'
    with open(embfile, 'r') as infile:
        data = json.load(infile)
    #print(data)

    query = input("Enter a description of the client's systems, or a file containing such: ")
    if os.path.isfile(query):
        query = open_file(query)
        print(query)
    results = search_index(query, data)
    #print(results)
    #sys.exit(0)
    ####### for testing: ######
    results = results[0:2]
    ######
    answers = list()
    # answer the same question for all returned chunks
    print('creating sub-answers for each relevant chunk')
    with open('prompt_chunk.yaml', 'r') as f:
        template = yaml.safe_load(f)
    allprompts = [parse_template_prompt(template, query, result['content']) for result in results]
    #print(allprompts)
    #sys.exit()
    allcompletions = asyncio.run(concurrent_gpt_completions(message_groups=allprompts))
    with open('async_completion_test.json', 'w') as f:
        json.dump(allcompletions, f)
    sys.exit()

    
    for result in tqdm(results):
        prompt = open_file('prompt_chunk.txt').replace('<<PASSAGE>>', result['content']).replace('<<QUERY>>', query)
        answer = gpt_completion(prompt)
        print('\n\n', answer)
        answers.append(answer)
    # summarize the answers together
    all_answers = '\n\n'.join(answers)
    chunks = textwrap.wrap(all_answers, 10000)
    plan = chunks.pop(0) # also removes so won't be duplicated
    final = []
    for chunk in chunks:
        prompt = open_file('prompt_summary.txt').replace('<<QUERY>>', query).replace('<<MAIN_PASSAGE>>', plan).replace('<<ADDL_PASSAGE>>', chunk)
        plan = gpt_completion(prompt)
        final.append(plan)
    #print('\n\n=========\n\n', '\n\n'.join(final))
    print(plan)
    # save the answers
    i = 0
    fexist = True
    while fexist:
        i += 1
        fpath = 'Outputs/answer_questions_%04d.json' % i
        fexist = os.path.isfile(fpath)
    # now we have the filename
    with open(fpath, 'w') as outfile:
        json.dump(final, outfile, indent=2)


# test query:
# We have a system based on Windows 3.1 that has been upgraded with a TCP-IP stack from 2012 and we want to know if it has any DNS-related problems we should be worried about.
