import ollama
from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine
from rouge_score import rouge_scorer
import torch
from unieval import UniEval

#Commit Message, vulnerable & fixed versions of the function, CWE ID, and CVE information will manually be put into variables
Commit_msg= ""
vul_func = ""
fixed_func= ""
CWE_ID = ""
CVE_msg = ""
prompt = 'You will be given a vulnerable and patched version of a code function as well as its commit message. Identify the CWE ID for the function. ' \
'Then generate a 2-3 sentence natural language summary describing what the patch did and why it was implemented. Your response should be formatted as follows, “CWE ID:  Summary:” '
context_given = " Fixed version of function: "+fixed_func+" Vulnerable version of function: "+vul_func+" Commit Message: "+Commit_msg
generated_response = ''
# Initialize the model used for cosine similarity comparison
model = SentenceTransformer('all-mpnet-base-v2')

#Function for finding cosine similarity between LLM generated response and CVE information 
def Cosine_Similarity(generated_response, CVE_msg):
    embedding1 = model.encode(generated_response, convert_to_tensor=False)  # Ensure output is a numpy array
    embedding2 = model.encode(CVE_msg, convert_to_tensor=False)  # Ensure output is a numpy array
    cosine_similarity = 1 - cosine(embedding1, embedding2)
    return cosine_similarity


#Function for finding Rouge score between LLM generated response and CVE information returns list with 3 rouge scores with different weights for precison, recall, fmeasure
def ROUGE(generated_response, CVE_msg):
    # Initialize the ROUGE scorer
    scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'], use_stemmer=True)

    # Compute ROUGE scores
    scores = scorer.score(generated_response, CVE_msg)

    return scores


#function used to evaluate
def Unievaluation(reference, candidate, dimension="coherence"):
   
    # Initialize UniEval
    evaluator = UniEval()

    # Prepare the input data
    input_data = [{
        "source": reference,  # Reference text
        "candidate": candidate  # Candidate text
    }]

    # Evaluate the candidate text
    scores = evaluator.evaluate(input_data, dimension=dimension)

    return scores[0]

def Overall_Score(generated_response, CVE_msg):
    cosine_similarity = Cosine_Similarity(generated_response, CVE_msg)
    rouge_scores = ROUGE(generated_response, CVE_msg)
    unieval_scores = Unievaluation(generated_response, CVE_msg, dimension='coherence')
    print("Cosine Similarity Score:", cosine_similarity)
    print("ROUGE-1 Score:", rouge_scores['rouge1'])
    print("ROUGE-2 Score:", rouge_scores['rouge2'])
    print("ROUGE-L Score:", rouge_scores['rougeL'])
    print("UniEval Coherence Score:", unieval_scores['coherence'])

    


#print("ROUGE-1 Score:", rouge_scores['rouge1'])
#print("ROUGE-2 Score:", rouge_scores['rouge2'])
#print("ROUGE-L Score:", rouge_scores['rougeL'])
    


#Streams generated response from llama3 model and saves response to generated_response variable
stream = ollama.chat(model='llama3', messages=[{
    'role': 'user',
    'content': prompt + context_given
}], stream=True)

for chunk in stream:
    if 'message' in chunk:
        print(chunk['message']['content'], end='', flush=True)
        generated_response += chunk['message']['content']
       