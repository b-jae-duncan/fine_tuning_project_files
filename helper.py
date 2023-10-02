
import os
import csv
import re
import json
import datetime

import hashlib
from pathlib import Path
from datetime import datetime
from dateutil import relativedelta
import tiktoken

import androguard
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
from androguard.decompiler.decompiler import DecompilerJADX
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.analysis import analysis
from androguard.core.bytecodes import dvm
from androguard.decompiler.decompiler import DecompilerDAD





API_CALLS = ("getDeviceId", "getCellLocation", "setFlags", "addFlags", "setDataAndType",
             "putExtra", "init", "query", "insert", "update", "writeBytes", "write",
             "append", "indexOf", "substring", "startService", "getFilesDir",
             "openFileOutput", "getApplicationInfo", "getRunningServices", "getMemoryInfo",
             "restartPackage", "getInstalledPackages", "sendTextMessage", "getSubscriberId",
             "getLine1Number", "getSimSerialNumber", "getNetworkOperator", "loadClass",
             "loadLibrary", "exec", "getNetworkInfo", "getExtraInfo", "getTypeName",
             "isConnected", "getState", "setWifiEnabled", "getWifiState", "setRequestMethod",
             "getInputStream", "getOutputStream", "sendMessage", "obtainMessage", "myPid",
             "killProcess", "readLines", "available", "delete", "exists", "mkdir", "ListFiles",
             "getBytes", "valueOf", "replaceAll", "schedule", "cancel", "read", "close",
             "getNextEntry", "closeEntry", "getInstance", "doFinal", "DESKeySpec",
             "getDocumentElement", "getElementByTagName", "getAttribute")
"""
Run extraction for one file to get headers for csv file
"""
def get_headers(directory, metadata, labels):
    arr = os.listdir(directory)

    if len(arr) <= 0:
        raise Exception(f'No files in provided directory {directory}')

    #get apk features for single apk
    apk = arr[0]
    filename = f'{directory}/{apk}'
    apkobj = APK(filename)
    # Create DalvikVMFormat Object
    dexobj = DalvikVMFormat(apkobj)
    # Create Analysis Object
    analysisobj = Analysis(dexobj)

    headers = get_apk_features(filename, apkobj, dexobj, analysisobj, metadata, labels)

    return list(headers.keys())

def get_headers_v2(file, full_path):
    apk_name = file['apk_name']
    file_name = file['file_name']
    label = file['label']
    metadata = file['metadata']

    apk_path = f'{full_path}/{apk_name}'
    # apkobj = APK(apk_path)
    # # Create DalvikVMFormat Object
    # dexobj = DalvikVMFormat(apkobj)
    # # Create Analysis Object
    # analysisobj = Analysis(dexobj)

    # apkobj, dexobj, analysisobj = AnalyzeAPK(apk_path)

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
    

    features = get_apk_features_2(apk_path, apkobj, dexobj, analysisobj, label, metadata)

    return list(features.keys())

def get_apk_features(filename, apkobj, dexobj, analysisobj, metadata, labels):
    file_name = Path(filename).stem
    results = {}
    try:
        # a, _, dx = AnalyzeAPK(filename)
        dexobj.set_vmanalysis(analysisobj)
        dexobj.set_decompiler(DecompilerDAD(dexobj, analysisobj))
    except: 
        return None

    curr_apk_metadata = next((item for index, item in enumerate(metadata) if item['sha256'] == file_name), -1)
    apk_metadata_index = metadata.index(curr_apk_metadata)

    results['label'] = labels[apk_metadata_index]
    results['dex_date']  = curr_apk_metadata['dex_date']

    # results['android_version_code'] = apkobj.get_androidversion_code()
    # results['android_version_name'] = apkobj.get_androidversion_name()
    # results['max_sdk'] = apkobj.get_max_sdk_version()
    # results['min_sdk'] = apkobj.get_min_sdk_version()
    # results['libraries'] = apkobj.get_libraries()
    results['filename'] = apkobj.get_filename()
    # results['target_sdk'] = apkobj.get_target_sdk_version()
    # results['md5'] = hashlib.md5(apkobj.get_raw()).hexdigest()
    # results['sha256'] = hashlib.sha256(apkobj.get_raw()).hexdigest()

    # results['permissions'] = apkobj.get_permissions()
    results['permissions'] = parse_permissions(apkobj.get_details_permissions())

    # results['main_activity'] = apkobj.get_main_activity()
    results['num_activities'] = len(apkobj.get_activities())
    # results['receivers'] = apkobj.get_receivers()
    # results['providers'] = apkobj.get_providers()
    results['num_services'] = len(apkobj.get_services())
    results['num_files'] = len(apkobj.get_files())
    results['certificates'] = get_cert_info(apkobj)

    # results['strings'] = dexobj.get_strings()
    strings = dexobj.get_strings()
    results['embedded_urls'] = list(filter(any_url_match, strings))
    # results['is_obfuscation'] = 1 if analysis.is_ascii_obfuscation(dexobj) else 0
    # results['class_names'] = [c.get_name() for c in dexobj.get_classes()]
    # results['method_names'] = [m.get_name() for m in dexobj.get_methods()]
    # results['field_names'] = [f.get_name() for f in dexobj.get_fields()]
    results['api_calls'] = get_api_calls(filename)
    results['instruction_sequence'] = get_disassem_instr(filename)
    results['intents'] = get_intents(apkobj)

    results['token_size'] = num_tokens_from_string(str(results), 'r50k_base')
    return results

    
def get_apk_features_2(filename, apkobj, dexobj, analysisobj, label, metadata):
    file_name = Path(filename).stem
    results = {}
    # try:
    #     # a, _, dx = AnalyzeAPK(filename)
    #     dexobj.set_vmanalysis(analysisobj)
    #     dexobj.set_decompiler(DecompilerDAD(dexobj, analysisobj))
    # except: 
    #     print('Error here')
    #     return None

    results['label'] = label
    results['dex_date']  = metadata['dex_date']

    # results['android_version_code'] = apkobj.get_androidversion_code()
    # results['android_version_name'] = apkobj.get_androidversion_name()
    # results['max_sdk'] = apkobj.get_max_sdk_version()
    # results['min_sdk'] = apkobj.get_min_sdk_version()
    # results['libraries'] = apkobj.get_libraries()
    results['filename'] = file_name
    # results['target_sdk'] = apkobj.get_target_sdk_version()
    # results['md5'] = hashlib.md5(apkobj.get_raw()).hexdigest()
    # results['sha256'] = hashlib.sha256(apkobj.get_raw()).hexdigest()

    # results['permissions'] = apkobj.get_permissions()
    results['permissions'] = parse_permissions(apkobj.get_details_permissions())

    # results['main_activity'] = apkobj.get_main_activity()
    results['num_activities'] = len(apkobj.get_activities())
    # results['receivers'] = apkobj.get_receivers()
    # results['providers'] = apkobj.get_providers()
    results['num_services'] = len(apkobj.get_services())
    results['num_files'] = len(apkobj.get_files())
    results['certificates'] = get_cert_info(apkobj)

    # results['strings'] = dexobj.get_strings()
    strings = dexobj.get_strings()
    results['embedded_urls'] = list(filter(any_url_match, strings))
    # results['is_obfuscation'] = 1 if analysis.is_ascii_obfuscation(dexobj) else 0
    # results['class_names'] = [c.get_name() for c in dexobj.get_classes()]
    # results['method_names'] = [m.get_name() for m in dexobj.get_methods()]
    # results['field_names'] = [f.get_name() for f in dexobj.get_fields()]
    results['api_calls'] = get_api_calls(filename)
    # results['instruction_sequence'] = get_disassem_instr(filename)
    results['intents'] = get_intents_2(apkobj)

    results['token_size'] = num_tokens_from_string(str(results), 'r50k_base')
    return results

def get_apk_features_v3(filename, apkobj, dexobj, analysisobj, metadata):
    file_name = Path(filename).stem
    results = {}
    # try:
    #     # a, _, dx = AnalyzeAPK(filename)
    #     dexobj.set_vmanalysis(analysisobj)
    #     dexobj.set_decompiler(DecompilerDAD(dexobj, analysisobj))
    # except: 
    #     print('Error here')
    #     return None

    # value = data[key] if key in data else None

    results['label'] = metadata['label'] if 'label' in metadata else None
    results['dex_date']  = metadata['dex_date'] if 'dex_date' in metadata else None
    results['family'] = metadata['family'] if 'family' in metadata else None
    results['class'] = metadata['class'] if 'class' in metadata else None

    # results['android_version_code'] = apkobj.get_androidversion_code()
    # results['android_version_name'] = apkobj.get_androidversion_name()
    # results['max_sdk'] = apkobj.get_max_sdk_version()
    # results['min_sdk'] = apkobj.get_min_sdk_version()
    # results['libraries'] = apkobj.get_libraries()
    results['filename'] = file_name
    # results['target_sdk'] = apkobj.get_target_sdk_version()
    # results['md5'] = hashlib.md5(apkobj.get_raw()).hexdigest()
    # results['sha256'] = hashlib.sha256(apkobj.get_raw()).hexdigest()

    # results['permissions'] = apkobj.get_permissions()
    results['permissions'] = parse_permissions(apkobj.get_details_permissions())

    # results['main_activity'] = apkobj.get_main_activity()
    results['num_activities'] = len(apkobj.get_activities())
    # results['receivers'] = apkobj.get_receivers()
    # results['providers'] = apkobj.get_providers()
    results['num_services'] = len(apkobj.get_services())
    results['num_files'] = len(apkobj.get_files())
    results['certificates'] = get_cert_info(apkobj)

    # results['strings'] = dexobj.get_strings()
    strings = dexobj.get_strings()
    results['embedded_urls'] = list(filter(any_url_match, strings))
    # results['is_obfuscation'] = 1 if analysis.is_ascii_obfuscation(dexobj) else 0
    # results['class_names'] = [c.get_name() for c in dexobj.get_classes()]
    # results['method_names'] = [m.get_name() for m in dexobj.get_methods()]
    # results['field_names'] = [f.get_name() for f in dexobj.get_fields()]
    results['api_calls'] = get_api_calls(filename)
    # results['instruction_sequence'] = get_disassem_instr(filename)
    results['intents'] = get_intents_2(apkobj)

    results['token_size'] = num_tokens_from_string(str(results), 'r50k_base')
    return results


def num_tokens_from_string(string: str, encoding_name: str) -> int:
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

def parse_permissions(permissions):
    permission_descriptions = []

    for permission in permissions:
        actual_perm = permission

        if permission.startswith('android.permission.'):
            actual_perm = permission.split('android.permission.')[1]

        if len(permissions[permission]) > 2:
            permission_descriptions.append(
            f'{actual_perm}: {permissions[permission][1]}')
        else:
            permission_descriptions.append(actual_perm)
    
    return permission_descriptions

def get_disassem_instr(apk_path):
    print('Extracting Opcode Instruction Sequence...')
    a, _, dx = AnalyzeAPK(apk_path)

    instructions = []

    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        for ins in m.get_instructions():
            # instructions.append(ins.get_op_value()) #get_op_value() --> Return the numerical value of the opcode
            instructions.append(ins.get_name())

    # generated_ngrams = generate_ngrams(instructions, 2)

    generated_ngrams = instructions
    # return set(generated_ngrams)
    return generated_ngrams

def generate_ngrams(list, n):
    """
    Generate n-grams for the list passed. 
    The order of n is passed as n in the function.
    """
    if (n > len(list)):
        n = len(list)
    return [tuple(list[i: i + n]) for i in range(len(list) - n + 1)]


def get_api_calls(apk_path):
    apicalls = []
    sensitive_api_calls = []

    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except:
        return None
    
    for test in d:
        for method in test.get_methods():
            for i in method.get_instructions():
                if i.get_name()[:6] == "invoke":
                    # get method desc
                    entire_call = i.get_output(0).split(',')[-1].strip()
                    # remove return value

                    # call = entire_call[:entire_call.index(')')+1]
                    # # split in class and method
                    # call = call.split('->')
                    # # method_class = type(call[0])
                    # ins_method = call[1].split('(')[0]
                    # # ins_method, params = call[1].split('(')
                    # # params = params.replace(')', '')

                    # apicalls.append(ins_method)
                    # apicall = "{0}.{1}({2})".format(method_class,
                    #                                 ins_method,
                    #                                 params)
                    # data = re.split('/',params)
                    
                    # for j in API_CALLS:
                    #     if ins_method in API_CALLS:
                    #         if ins_method in sensitive_api_calls:
                    #             continue
                    #         else:
                    #             sensitive_api_calls.append(ins_method)

                    for j in API_CALLS:
                        if j in entire_call:
                            if j in sensitive_api_calls:
                                continue
                            else:
                                sensitive_api_calls.append(j)
    #"<class 'str'>.getInstance(Ljava/lang/String;)"
    return sensitive_api_calls



def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)

    return obj

def any_url_match(string): 
    import re

    if re.match(r'(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})(\.[a-zA-Z0-9]{2,})?\/[a-zA-Z0-9]{2,}', string):
        return True
    else:
        return False

def get_intents_2(apkobj):
    try:
        activities = apkobj.get_activities()
        receivers = apkobj.get_receivers()
        services = apkobj.get_services()

        filter_list = []
        for i in activities:
            filters = apkobj.get_intent_filters("activity", i)
            if len(filters) > 0:
                filter_list.append(filters['action'])
        for i in receivers:
            filters = apkobj.get_intent_filters("receiver", i)
            if len(filters) > 0:
                filter_list.append(filters['action'])
        for i in services:
            filters = apkobj.get_intent_filters("service", i)
            if len(filters) > 0:
                filter_list.append(filters['action'])
        
        return filter_list
    except:
        print('Error retrieving intents')
        return None
def get_intents(apkobj):
    # apkobj = APK(apk_path, testzip=True)
   
    activities = apkobj.get_activities()
    receivers = apkobj.get_receivers()
    services = apkobj.get_services()

    filter_list = []
    for i in activities:
        filters = apkobj.get_intent_filters("activity", i)
        if len(filters) > 0:
            filter_list.append(filters['action'])
    for i in receivers:
        filters = apkobj.get_intent_filters("receiver", i)
        if len(filters) > 0:
            filter_list.append(filters['action'])
    for i in services:
        filters = apkobj.get_intent_filters("service", i)
        if len(filters) > 0:
            filter_list.append(filters['action'])
    
    return filter_list


def get_cert_info(apkobj):
    certificate_info = {}
    if apkobj.is_signed():
        # Test if signed v1 or v2 or both
        certificate_info['cert_summary'] = "APK is signed with {}".format("both" if apkobj.is_signed_v1() and
        apkobj.is_signed_v2() else "v1" if apkobj.is_signed_v1() else "v2")
    else: 
        certificate_info['cert_summary'] = 'APK is not signed'

    certificate_info['certs'] = []

    # Iterate over all certificates
    for cert in apkobj.get_certificates():
        # Each cert is now a asn1crypt.x509.Certificate object
        # From the Certificate object, we can query stuff like:
        delta = relativedelta.relativedelta(cert.not_valid_after, cert.not_valid_before)        
        
        try:
            is_self_issued = cert.self_issued
        except AttributeError as e:
            print("get_cert_info AttributeError:", e)
            continue
        except ValueError as e:
            print("get_cert_info ValueError:", e)
            continue
        
        if is_self_issued:
            cert_info = f'Self signed and valid for {delta.years} years, {delta.months} months {delta.days} days'
        else:
            cert_info = f'Not self signed and valid for {delta.years} years, {delta.months} months {delta.days} days'    

        certificate_info['certs'].append(cert_info)
    
    return certificate_info

