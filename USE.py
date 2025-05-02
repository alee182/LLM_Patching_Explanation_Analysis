import tensorflow_hub as hub
import numpy as np

model = hub.load("")
sentences = [
    "I love machine learning.",
    "Artificial intelligence is fascinating.",
    "The weather is nice today."
]

# Get embeddings
embeddings = model(sentences)

# Cosine similarity between sentence 0 and sentence 1
cos_sim = np.inner(embeddings[0], embeddings[1])
print("Cosine Similarity:", cos_sim)
