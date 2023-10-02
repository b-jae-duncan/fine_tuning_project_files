## Memory Efficient Fine-Tuning of Large Language Models for Learning Representations and Detection of Android Malware
### Project Artifacts

The following is a list of the files created/generated for the above mentioned dissertation.

#### Requirements:


#### Files:
- `extract_features_job_script.qsub.sh`: the script used to schedule the array jobs on the UCL HPC cluster. The following values must be replaced in the script:
    - APK_DIR: direcrtory where the APKs are located
    - OUTPUT_DIR: directory where APK features would be stored
    - APK_META: json file of the array of APK metadata
    - APK_NAMES: json file with APK names to be processed. Should be a multidimensional array of batches of APK names in the APK directory. `apk_names.json` file in this directory is the actual file used for the project

    The script should also be in the same directory as the feature extraction python script discussed below. Additionally, the requirements.txt file should also be present in the directory

- `extract_features_batch.py`: used to extract the features of a batch of APKs. It takes the following arguments:
    - apk_dir: direcrtory where the APKs are located
    - apk_meta: json file of the array of APK metadata
    - apk_names_file: json file with APK names to be processed. Should be a multidimensional array of batches of APK names
    - output_dir: directory where APK features would be stored
    - ncores: Number of cores used for multiprocessing 
    - sge_task_id: index of the current element in the apk_names_files being processed

- `helper.py`: used by the `extract_features_batch.py` script to extract APK features from APKs

- `fine_tuning_script.ipynb`: script used for prompt formatting and fine-tuning using Llama 2 and QLoRA

- `dataset/batch-*.json`: Extracted features datasets for all APKs in batches (github does not allow upload of files over 100MB)
- `concat_dataset.py`: concatenate all files inside `dataset` directory. New file created will be `apk_features_concat.json`
- `read_dataset.py`: use this script to preview the dataset and its features