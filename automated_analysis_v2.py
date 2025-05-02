from datasets import load_dataset
import json
import ollama
from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine
from rouge_score import rouge_scorer
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import os
import numpy as np
from bert_score import score


os.environ["TOKENIZERS_PARALLELISM"] = "false"

#Function for calculation Cosine Similarity
embedding_creation_model = SentenceTransformer('all-mpnet-base-v2')
def Cosine_Similarity(generated_response, CVE_message):
    embedding1 = embedding_creation_model.encode(str(generated_response), convert_to_tensor=False)  # Ensure output is a numpy array
    embedding2 = embedding_creation_model.encode(CVE_message, convert_to_tensor=False)  # Ensure output is a numpy array
    cosine_similarity = 1 - cosine(embedding1, embedding2)
    return cosine_similarity


#Function for finding Rouge score between LLM generated response and CVE information returns list with 3 rouge scores with different weights for precison, recall, fmeasure
def ROUGE(generated_response, CVE_msg):  
    scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'], use_stemmer=True)
    scores = scorer.score(generated_response, CVE_msg)

    return scores

def BERT_Scoring(generated_response, reference):
    P, R, F1 = score([str(generated_response)], [reference], lang="en", model_type="microsoft/deberta-xlarge-mnli")
    return {
        "BERTScore Precision": f"{P.item():.4f}",
        "BERTScore Recall": f"{R.item():.4f}",
        "BERTScore F1": f"{F1.item():.4f}"
    }

#Returns CVE Explanation from CVE webpage metadata link
def cvedetails_webscrape(cve_link):
    # Set up Chrome with the WebDriver Manager 
    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # Run in headless mode (without opening a window)

    # Create a WebDriver instance
    driver = webdriver.Chrome(service=service, options=options)

    
    url = cve_link

   
    driver.get(url)

    # Find the div by its ID and class
    cve_summary_div = driver.find_element(By.ID, 'cvedetailssummary')

   
    cve_summary = cve_summary_div.text
    driver.quit()
    return cve_summary


#Seperates LLM Generated response into variables for cwe, cve and summary
def extract_cwe_cve_summary(text):
    
    cwe_id = None
    cve_id = None
    summary = None

    # Split the text at each known field
    if "CWE ID:" in text:
        cwe_id = text.split("CWE ID:")[1].split("CVE_ID:")[0].strip()

    if "CVE_ID:" in text:
        cve_id = text.split("CVE_ID:")[1].split("Summary:")[0].strip()

    if "Summary:" in text:
        summary = text.split("Summary:")[1].strip()

    return {'CWE_ID': cwe_id, 'CVE_ID': cve_id, 'Summary': summary}



#Returns Dictionary of Llama3 guess at cwe, cve and summary
def Ollama_Model_Analysis(Context_Given):
    generated_response = ""
    stream = ollama.chat(model='llama3.1', messages=[{
    "role": "system",
    "content": "You are a vulnerability analyst. Given code changes and a commit message, identify the correct CWE and CVE IDs. Follow the required output format exactly, with no extra text or line breaks."
  },
  {
    "role": "user",
    "content": Context_Given
  }], stream=True)

    for chunk in stream:
        if 'message' in chunk:
            content = chunk['message']['content']
            #print(content, end='', flush=True)  # Optionally print the content as it arrives
            generated_response += content  

    #calculates the amount of tokens used per query
    #tokenizer = AutoTokenizer.from_pretrained("meta-llama/Meta-Llama-3-8B")
    #tokens = tokenizer.encode(generated_response)
    

    return extract_cwe_cve_summary(generated_response)#, len(tokens)


def Mistral_Model_Analysis(Context_given):
    generated_response = ""
    stream = ollama.chat(model='mistral', messages=[{
    "role": "system",
    "content": "You are a vulnerability analyst. Given code changes and a commit message, identify the correct CWE and CVE IDs. Follow the required output format exactly, with no extra text or line breaks."
  },
  {
    "role": "user",
    "content": Context_given
  }], stream=True)

    for chunk in stream:
        if 'message' in chunk:
            content = chunk['message']['content']
            #print(content, end='', flush=True)  # Optionally print the content as it arrives
            generated_response += content  
    return extract_cwe_cve_summary(generated_response)

#adds LLM generated information about vul to proper location in json object
def add_analysis_to_json(json_object, model_name, model_analysis, cosine_score, BERTScore):
    json_object[model_name +" Summary"] = model_analysis.get('Summary')
    json_object[model_name +" CWE"] = model_analysis.get('CWE_ID')
    json_object[model_name +" CVE"] = model_analysis.get('CVE_ID')
    json_object[model_name +" BERT Score"] = BERTScore
    json_object[model_name +" Cosine_Similarity"] = cosine_score
    return json_object

#converts non-compatible json floats/integers
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.floating):  # Handles float32, float64
            return float(obj)
        if isinstance(obj, np.integer):  # Handles int32, int64
            return int(obj)
        return super().default(obj)

dataset = load_dataset("bstee615/bigvul", split='train')

#filters out all non vulnerable datasets, num of rows after filter: 8714
#modify to and row["CWE ID"] is not none for non CWE specific run
filtered_dataset = dataset.filter(lambda row: row["vul"] == 1 and row["CWE ID"] == "CWE-787")

#setup for saving data set in json objects
output_file = 'vulpatch_analysis_cot_cwe-787.json'
data_to_save = []

#modify to get amount of dataset entries 
start_index = 10
batch_size = 25
batch = filtered_dataset.select(range(start_index, min(start_index + batch_size, len(filtered_dataset))))


print(batch)
count = 1
#set up for LLM analysis
for instance in batch:
    
    instance_dict = {
        'codeLink': instance['codeLink'],
        'CVE ID': instance['CVE ID'],
        'CVE Details': str(cvedetails_webscrape(instance['CVE Page'])),
        'CWE ID': instance['CWE ID'],
        'commit_message': str(instance['commit_message']),
        'fixed_function': str(instance['func_after']),
        'vul_function': str(instance['func_before']),
        'llama3.1 Summary': '',
        'llama3.1 CWE': '',
        'llama3.1 CVE': '',
        'llama3.1 BERT Score': {},
        'llama3.1 Cosine_Similarity': '',
        # add Overall score entry once setup
        'Mistral Summary': '',
        'Mistral CWE': '',
        'Mistral CVE': '',
        'Mistral Cosine_Similarity': '',
        'Mistral BERT Score': {},
        'Tokens Used': ''

        
        
    }
    prompt = r"You will be given a vulnerable and patched version of a code function, along with its commit message. Follow the steps below and show your reasoning clearly for each step. Use the provided keys exactly as written. At the end, print only the final answer in a single line using the required format. 1. Analyze the vulnerable code and describe the issue. 2. Analyze the patched code and describe what was fixed or changed. 3. Interpret the commit message to understand the developer's intent. 4. Identify the most likely CWE ID. 5. Identify the most likely CVE ID (or write UNKNOWN if not known). 6. Write a concise two-sentence summary explaining the patch and its purpose. 7. Output the final answer in this format (no extra text or line breaks): CWE ID: CWE-XXX CVE_ID: CVE-XXXX-XXXX Summary: [your summary here]"
    Context_Given = prompt + " Fixed version of function: "+ instance_dict.get("fixed_function")+" Vulnerable version of function: "+instance_dict.get('vul_function')+" Commit Message: "+instance_dict.get('commit_message')
    #add ,token_amount for token feature
    llama31_analysis = Ollama_Model_Analysis(Context_Given)
    print("running  ollama model: ", count)
    
    ollama_cosine_score = Cosine_Similarity(llama31_analysis.get('Summary'), instance_dict.get('CVE Details'))
    ollama_BERTScore = BERT_Scoring(llama31_analysis.get('Summary'), instance_dict.get('CVE Details'))
    finished_dic = add_analysis_to_json(instance_dict, 'llama3.1', llama31_analysis, ollama_cosine_score, ollama_BERTScore)

    mistral_analysis =  Mistral_Model_Analysis(Context_Given)
    print("running mistral model: ", count)
    count += 1
    mistral_cosine_score = Cosine_Similarity(mistral_analysis.get('Summary'), instance_dict.get('CVE Details'))
    mistral_BERTScore = BERT_Scoring(mistral_analysis.get('Summary'), instance_dict.get('CVE Details'))

    #instance_dict = instance_dict["Tokens Used"] = token_amount
    finished_dic = add_analysis_to_json(instance_dict, 'Mistral', mistral_analysis, mistral_cosine_score, mistral_BERTScore)
    # keep adding to finished json with other models before transaferring to json file
    data_to_save.append(finished_dic)


with open(output_file, "w") as json_file:
    json.dump(data_to_save, json_file, indent=4, cls=NumpyEncoder)