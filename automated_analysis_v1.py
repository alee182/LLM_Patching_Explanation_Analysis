import ollama
from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine
from rouge_score import rouge_scorer
import torch
from utils import convert_to_json
from metric.evaluator import get_evaluator

#Commit Message, vulnerable & fixed versions of the function, CWE ID, and CVE information will manually be put into variables
Commit_msg= "posix-timers: Sanitize overrun handling  The posix timer overrun handling is broken because the forwarding functions can return a huge number of overruns which does not fit in an int. As a consequence timer_getoverrun(2) and siginfo::si_overrun can turn into random number generators.  The k_clock::timer_forward() callbacks return a 64 bit value now. Make k_itimer::ti_overrun[_last] 64bit as well, so the kernel internal accounting is correct. 3Remove the temporary (int) casts.  Add a helper function which clamps the overrun value returned to user space via timer_getoverrun(2) or siginfo::si_overrun limited to a positive value between 0 and INT_MAX. INT_MAX is an indicator for user space that the overrun value has been clamped."
vul_func = 'static void common_hrtimer_rearm(struct k_itimer *timr) { struct hrtimer *timer = &timr->it.real.timer;  if (!timr->it_interval) return;  timr->it_overrun += (unsigned int) hrtimer_forward(timer, timer->base->get_time(), timr->it_interval); hrtimer_restart(timer); }'
fixed_func = 'static void common_hrtimer_rearm(struct k_itimer *timr) { struct hrtimer *timer = &timr->it.real.timer;  if (!timr->it_interval) return;  timr->it_overrun += hrtimer_forward(timer, timer->base->get_time(), timr->it_interval); hrtimer_restart(timer); }'
#CWE_ID = "CWE-119"
CVE_msg = 'An issue was discovered in the Linux kernel through 4.17.3. An Integer Overflow in kernel/time/posix-timers.c in the POSIX timer code is caused by the way the overrun accounting works. Depending on interval and expiry time values, the overrun can be larger than INT_MAX, but the accounting is int based. This basically makes the accounting values, which are visible to user space via timer_getoverrun(2) and siginfo::si_overrun, random. For example, a local user can cause a denial of service (signed integer overflow) via crafted mmap, futex, timer_create, and timer_settime system calls.'

prompt = r'You will be given a vulnerable and patched version of a code function as well as its commit message. Identify the CWE ID for the function and  the CVE_ID for  the function Then generate a 2 sentence natural language summary describing what the patch did and why it was implemented. Do not give any further information than what is asked. Your response should be formatted as follows, "CWE ID: ___ CVE_ID: ___  Summary: ___  do not use /n in your response"'
context_given = " Fixed version of function: "+fixed_func+" Vulnerable version of function: "+vul_func+" Commit Message: "+Commit_msg
generated_response = ''
# Initialize the model used for cosine similarity comparison
model = SentenceTransformer('all-mpnet-base-v2')

#Function for finding cosine similarity between LLM generated response and CVE information 
def Cosine_Similarity(generated_response, CVE_message):
    embedding1 = model.encode(generated_response, convert_to_tensor=False)  # Ensure output is a numpy array
    embedding2 = model.encode(CVE_message, convert_to_tensor=False)  # Ensure output is a numpy array
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



def Overall_Score(generated_response, CVE_msg):
    cosine_similarity = Cosine_Similarity(generated_response, CVE_msg)
    rouge_scores = ROUGE(generated_response, CVE_msg)
    unieval_scores = Unievaluation(generated_response, CVE_msg, dimension='coherence')
    print("Cosine Similarity Score:", cosine_similarity)
    print("ROUGE-1 Score:", rouge_scores['rouge1'])
    print("ROUGE-2 Score:", rouge_scores['rouge2'])
    print("ROUGE-L Score:", rouge_scores['rougeL'])
   # print("UniEval Coherence Score:", unieval_scores['coherence'])

    


#print("ROUGE-1 Score:", rouge_scores['rouge1'])
#print("ROUGE-2 Score:", rouge_scores['rouge2'])
#print("ROUGE-L Score:", rouge_scores['rougeL'])
    


#Streams generated response from llama3 model and saves response to generated_response variable
generated_response = ""  # Initialize the variable to hold the generated response

stream = ollama.chat(model='llama3', messages=[{
    'role': 'user',
    'content': prompt + context_given
}], stream=True)

for chunk in stream:
    if 'message' in chunk:
        content = chunk['message']['content']
        print(content, end='', flush=True)  # Optionally print the content as it arrives
        generated_response += content  # Save the content to the variable


Analysis_items = extract_cwe_cve_summary(generated_response)
print("\n")
print(Analysis_items)
Overall_Score(Analysis_items.get('Summary'), CVE_msg)

       