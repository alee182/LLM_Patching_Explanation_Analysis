from datasets import load_dataset
import json
import ollama
from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine
from rouge_score import rouge_scorer
import torch
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

#Function for calculation Cosine Similarity
embedding_creation_model = SentenceTransformer('all-mpnet-base-v2')
def Cosine_Similarity(generated_response, CVE_message):
    embedding1 = embedding_creation_model.encode(generated_response, convert_to_tensor=False)  # Ensure output is a numpy array
    embedding2 = embedding_creation_model.encode(CVE_message, convert_to_tensor=False)  # Ensure output is a numpy array
    cosine_similarity = 1 - cosine(embedding1, embedding2)
    return cosine_similarity


#Function for finding Rouge score between LLM generated response and CVE information returns list with 3 rouge scores with different weights for precison, recall, fmeasure
def ROUGE(generated_response, CVE_msg):  
    scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'], use_stemmer=True)
    scores = scorer.score(generated_response, CVE_msg)

    return scores

def Overall_Score(generated_response, CVE_msg):
    cosine_similarity = Cosine_Similarity(generated_response, CVE_msg)
    rouge_scores = ROUGE(generated_response, CVE_msg)
    #unieval_scores = Unievaluation(generated_response, CVE_msg, dimension='coherence')
    print("Cosine Similarity Score:", cosine_similarity)
    print("ROUGE-1 Score:", rouge_scores['rouge1'])
    print("ROUGE-2 Score:", rouge_scores['rouge2'])
    print("ROUGE-L Score:", rouge_scores['rougeL'])

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
    stream = ollama.chat(model='llama3', messages=[{
    'role': 'user',
    'content': Context_Given
}], stream=True)

    for chunk in stream:
        if 'message' in chunk:
            content = chunk['message']['content']
            #print(content, end='', flush=True)  # Optionally print the content as it arrives
            generated_response += content  
    return extract_cwe_cve_summary(generated_response)

#adds LLM generated information about vul to proper location in json object
def add_analysis_to_json(json_object, model_name, model_analysis, cosine_score, rouge_score):
    json_object[model_name +" Summary"] = model_analysis.get('Summary')
    json_object[model_name +" CWE"] = model_analysis.get('CWE_ID')
    json_object[model_name +" CVE"] = model_analysis.get('CVE_ID')
    json_object[model_name +" Rouge_Score"] = rouge_score
    json_object[model_name +" Cosine_Similarity"] = cosine_score
    return json_object



dataset = load_dataset("bstee615/bigvul", split='train')

#filters out all non vulnerable datasets, num of rows after filter: 8714
filtered_dataset = dataset.filter(lambda row: row["vul"] == 1 and row["CWE ID"] is not None)

#setup for saving data set in json objects
output_file = 'dataset_features.json'
data_to_save = []

batch_size = 5 
'''
# runs the entire dataset in batches
for i in range(0, len(filtered_dataset), batch_size):
    batch = filtered_dataset[i:i+batch_size]
    print(f"Processing batch {i//batch_size + 1}")
'''

batch = filtered_dataset.select(range(batch_size))

print(batch)

#set up for LLM analysis
for instance in batch:
    instance_dict = {
        'codeLink': instance['codeLink'],
        'CVE ID': instance['CVE ID'],
        'CVE Details': cvedetails_webscrape(instance['CVE Page']),
        'CWE ID': instance['CWE ID'],
        'commit_message': instance['commit_message'],
        'fixed_function': instance['func_after'],
        'vul_function': instance['func_before'],
        'llama3 Summary': '',
        'llama3 CWE': '',
        'llama3 CVE': '',
        'llama3 Rouge_Score': {},
        'llama3 Cosine_Similarity': '',
        # add Overall score entry once setup
        'Mistral Summary': '',
        'Mistral CWE': '',
        'Mistral CVE': '',
        'Mistral Rouge_Score': {},
        'Mistral Cosine_Similarity': '',

        
        
    }
    prompt = r'You will be given a vulnerable and patched version of a code function as well as its commit message. Identify the CWE ID for the function and  the CVE_ID for  the function Then generate a 2 sentence natural language summary describing what the patch did and why it was implemented. Do not give any further information than what is asked. Your response should be formatted as follows, "CWE ID: ___ CVE_ID: ___  Summary: ___  do not use /n in your response"'
    Context_Given = prompt + " Fixed version of function: "+ instance_dict.get("fixed_function")+" Vulnerable version of function: "+instance_dict.get('vul_function')+" Commit Message: "+ instance_dict.get('commit_message')

    llama3_analysis = Ollama_Model_Analysis(Context_Given)
    ollama_cosine_score = Cosine_Similarity(llama3_analysis.get('Summary'), instance_dict.get('CVE Details'))
    ollama_rouge_score = ROUGE(llama3_analysis.get('Summary'), instance_dict.get('CVE Details')) 
    finished_json = add_analysis_to_json(instance_dict, 'llama3', llama3_analysis, ollama_cosine_score, ollama_rouge_score)