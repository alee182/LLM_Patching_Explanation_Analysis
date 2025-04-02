import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
# Model name
model_name = "mistralai/Mistral-7B-v0.1"

# Load tokenizer and model (forcing to CPU)
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype=torch.float32, device_map="cpu")

# Define prompt
prompt = "Explain quantum mechanics in simple terms."

# Tokenize input and move to CPU
inputs = tokenizer(prompt, return_tensors="pt").to("cpu")

# Generate output
with torch.no_grad():  # No gradients needed for inference
    output = model.generate(**inputs, max_new_tokens=1000)

# Decode and print response
response = tokenizer.decode(output[0], skip_special_tokens=True)
print(response)