from datasets import load_dataset
import json


dataset = load_dataset("bstee615/bigvul", split='train')

#filters out all non vulnerable datasets, num of rows after filter: 8714
filtered_dataset = dataset.filter(lambda row: row["vul"] == 1 and row["CWE ID"] is not None)

output_file = 'dataset_features.json'
data_to_save = []

batch_size = 5 
'''
for i in range(0, len(filtered_dataset), batch_size):
    batch = filtered_dataset[i:i+batch_size]
    print(f"Processing batch {i//batch_size + 1}")
'''

batch = filtered_dataset.select(range(batch_size))

print(batch)

for sample in batch: 
    sample_dict = {
        'CVE ID': sample['CVE ID'],
        'CVE Page': sample['CVE Page'],
        'CWE ID': sample['CWE ID'],
        'codeLink': sample['codeLink'],
        'commit_id': sample['commit_id'],
        'commit_message': sample['commit_message'],
        'func_after': sample['func_after'],
        'func_before': sample['func_before'],
        'lang': sample['lang'],
        'project': sample['project'],
        'vul': sample['vul'],
    }
    
    # Append the sample to the data list
    data_to_save.append(sample_dict)

# Write the data to a JSON file
with open(output_file, 'w') as json_file:
    json.dump(data_to_save, json_file, indent=4)

print(f'Data has been saved to {output_file}')


