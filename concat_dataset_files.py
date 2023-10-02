import os
import numpy as np
import json
import glob

batch_files_dir = './dataset'

def get_file_data(file):
  with open(file, 'rt') as f:
    data = json.load(f)

  return data


def concat_batches():
  
  files = []
  for file in os.listdir(batch_files_dir):
    if file.endswith('.json'):
      files.append(file)

  # files_array = np.array(files[:1])
  # print(files_array)
  # apk_meta_arr = np.vectorize(get_file_data)(files_array)
  apk_meta = []
  for file in files:
    batch_meta = get_file_data(f'{batch_files_dir}/{file}')
    for item in batch_meta:
      if item is None:
        batch_meta.remove(item)
      # else:
        # print(item)
    print(len(batch_meta))
    apk_meta.append(batch_meta)

  flat_list = [num for sublist in apk_meta for num in sublist]
  print(len(flat_list))

  print(len(apk_meta))

  with open('./apk_features_concat.json', 'w') as f:
    json.dump(flat_list, f)



concat_batches()