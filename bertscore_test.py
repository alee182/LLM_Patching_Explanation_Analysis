from bert_score import score

# Example sentences
ref_sentence = "Large language models generate human-like text."
gen_sentence = "AI models create realistic text using deep learning."




def BERT_Scoring(generated_response, reference):
    P, R, F1 = score([generated_response], [reference], lang="en", model_type="microsoft/deberta-xlarge-mnli")
    return {
        "BERTScore Precision": f"{P.item():.4f}",
        "BERTScore Recall": f"{R.item():.4f}",
        "BERTScore F1": f"{F1.item():.4f}"
    }

print(BERT_Scoring(gen_sentence, ref_sentence))
