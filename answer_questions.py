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
from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
    retry_if_not_exception_type
)  # for exponential backoff

# TO DO
# Add full logging
# Improve prompts
# of course add CWE and CPE
# Finally add Leviathan data

def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()


openai.api_key = open_file('openaiapikey_stanford.txt')


def retryCallback(retry_state):
    print(retry_state.outcome)
    return 'EMBED_FAIL'

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
def gpt3_completion(prompt, model='gpt-3.5-turbo-16k', temp=0.6, top_p=1.0, tokens=2000, freq_pen=0.25, pres_pen=0.0, stop=['<<END>>']):
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
            print(response)
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


if __name__ == '__main__':
    with open('nvdcve_embedding.json', 'r') as infile:
        data = json.load(infile)
    #print(data)
    while True:
        query = input("Enter your question here: ")
        #print(query)
        results = search_index(query, data)
        #print(results)
        #exit(0)
        answers = list()
        # answer the same question for all returned chunks
        print('creating sub-answers for each relevant chunk')
        for result in tqdm(results):
            prompt = open_file('prompt_answer.txt').replace('<<PASSAGE>>', result['content']).replace('<<QUERY>>', query)
            answer = gpt3_completion(prompt)
            print('\n\n', answer)
            answers.append(answer)
        # summarize the answers together
        all_answers = '\n\n'.join(answers)
        chunks = textwrap.wrap(all_answers, 10000)
        final = list()
        for chunk in chunks:
            prompt = open_file('prompt_summary.txt').replace('<<SUMMARY>>', chunk).replace('<<QUERY>>', query)
            summary = gpt3_completion(prompt)
            final.append(summary)
        print('\n\n=========\n\n', '\n\n'.join(final))

# test query:
# We have a system based on Windows 3.1 that has been upgraded with a TCP-IP stack from 2012 and we want to know if it has any DNS-related problems we should be worried about.
