import json
import pandas as pd 

def get_file_data(file):
  with open(file, 'rt') as f:
    data = json.load(f)

  return data


json_data = get_file_data(f'./apk_features_concat.json')

print(json_data[0])

json_data = [i for i in json_data if i is not None]

df = pd.DataFrame(json_data)
pd.set_option('display.max_columns', None)

print(df)
