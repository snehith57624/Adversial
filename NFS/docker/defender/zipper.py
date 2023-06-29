import zipfile
import os
import shutil
import IPython

def unzip(payload):
    dir_path = "/tmp/train/"
    file_path = "/tmp/train.zip"
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    open(file_path,'wb').write(payload)
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(dir_path)
    mw_path = os.path.join(dir_path,"malware/")
    gw_path = os.path.join(dir_path,"goodware/")
    mw_list = []
    for _file in os.listdir(mw_path):
        mw_list.append(os.path.join(mw_path,_file))
    gw_list = []
    for _file in os.listdir(gw_path):
        gw_list.append(os.path.join(gw_path,_file))
    return mw_list, gw_list
