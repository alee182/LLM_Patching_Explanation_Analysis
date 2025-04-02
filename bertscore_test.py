from bert_score import score

# Example sentences
ref_sentence = "Large language models generate human-like text."
gen_sentence = "AI models create realistic text using deep learning."

# Compute BERTScore
P, R, F1 = score([gen_sentence], [ref_sentence], lang="en", model_type="microsoft/deberta-xlarge-mnli")

print(f"BERTScore Precision: {P.item():.4f}")
print(f"BERTScore Recall: {R.item():.4f}")
print(f"BERTScore F1: {F1.item():.4f}")
