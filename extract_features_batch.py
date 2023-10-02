import argparse
import os
import json
from pathlib import Path
import multiprocessing
import time

from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
from androguard.decompiler.decompiler import DecompilerJADX
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.analysis import analysis
from androguard.core.bytecodes import dvm
from androguard.decompiler.decompiler import DecompilerDAD

from helper import get_headers_v2, get_apk_features_2, get_apk_features_v3


def get_metadata(meta_path, apk):
    with open(meta_path, 'rt') as f:
        metadata = json.load(f)

    try:
        apk_meta = metadata[apk]
        return apk_meta
    except KeyError:
        return None
    
def get_all_metadata(meta_path):
    with open(meta_path, 'rt') as f:
        metadata = json.load(f)
    return metadata
    
def analysis_app(apk_name, apk_dir, meta):
    print(f'Extracting Features for APK: {apk_name}')
    apk_path = f'{apk_dir}/{apk_name}'
    try:
        apkobj = APK(apk_path)
        dexobj = DalvikVMFormat(apkobj.get_dex())
        analysisobj = Analysis(dexobj)
        # vm = dvm.dexobjVMFormat(apkobj.get_dex())
        # vmx = analysis.uVMAnalysis(vm)
        dexobj.set_vmanalysis(analysisobj)
        dexobj.set_decompiler(DecompilerDAD(dexobj, analysisobj))
    except: 
        return None

    

    features = get_apk_features_v3(apk_path, apkobj, dexobj, analysisobj, meta)

    return features

def get_apk_filenames(filenames_path):
    with open(filenames_path, 'rt') as f:
        filenames = json.load(f)

    return filenames   


if __name__ == "__main__":
    start_time = time.perf_counter()
    args = argparse.ArgumentParser(prog='python3 extract_features_parallel.py', formatter_class=argparse.RawDescriptionHelpFormatter, description="Extract features from APKs in specified directory \n")
    args.add_argument("--sge_task_id", required=True, help="directory containing APK files")
    args.add_argument("--apk_dir", required=True, help="directory containing APK files")
    args.add_argument("--apk_meta", required=True, help="directory containing APK metadata and labels")
    args.add_argument("--apk_names_file", required=True, help="file containing APK names as chunks")
    args.add_argument("--output_dir", required=True, help="directory to store the APK features extracted")
    args.add_argument("--ncores", required=False, help="number of cores for the job")

    args = args.parse_args()

    apk_dir_name = args.apk_dir
    apk_meta = args.apk_meta
    apk_names_file = args.apk_names_file
    output_dir = args.output_dir
    sge_task_id = int(args.sge_task_id)
    cores = args.ncores

    all_apks = get_apk_filenames(apk_names_file) #load all in chunks

    if cores is None:
        cores = multiprocessing.cpu_count()
    else: 
        cores = int(args.ncores)

    try:
        current_apk_chunk = all_apks[sge_task_id]
    except IndexError:
        print(f'APK chunk not found for the index provided: {sge_task_id}')
        exit(0)

    metadata = get_all_metadata(apk_meta)

    args = [(apk, apk_dir_name, metadata[Path(apk).stem]) for apk in current_apk_chunk]

    with multiprocessing.Pool(processes=cores) as pool:
       apk_features = pool.starmap(analysis_app, args)

    with open(f'{output_dir}/batch-{sge_task_id}.json', 'w') as f:
        json.dump(apk_features, f)


    finish_time = time.perf_counter()
    print(f'APK features extraction for batch {sge_task_id} complete {finish_time-start_time}')
    print('-------------------------')