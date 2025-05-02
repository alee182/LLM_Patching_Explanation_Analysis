import ollama
Context_given = "how much is a good price for a used acoustic guitar?"
generated_response = ""
stream = ollama.chat(model='mistral', messages=[{
    'role': 'user',
    'content': Context_given
}], stream=True)
for chunk in stream:
    if 'message' in chunk:
        content = chunk['message']['content']
        #print(content, end='', flush=True)  # Optionally print the content as it arrives
        generated_response += content  
print(generated_response)