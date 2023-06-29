import os
import shutil
import zipfile
import pathlib

# Create a Zip file to host malware and goodware for training
def build_zip(malware,goodware):
    # I could write files directly to the archive
    # I opted to write to a custom tmp dir to be able to inspect it

    # TMP dir to store the files
    dir_path = "/tmp/train/"
    # TMP Zip files
    # Always the same file, not safe for multithread
    file_path = "/tmp/train.zip"
    # If exists, remove all files and dir
    # It is important because sometimes files remain after crashes
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    if os.path.exists(file_path):
        os.remove(file_path)

    # TMP dir inside the "archive" dir
    mw_path = os.path.join(dir_path,"malware/")
    gw_path = os.path.join(dir_path,"goodware/")

    os.mkdir(dir_path)
    os.mkdir(mw_path)
    os.mkdir(gw_path)

    # Add malware and goodware files to the "archive" dir
    for _file in os.listdir(malware):
        _src_path = os.path.join(malware,_file)
        shutil.copy(_src_path,mw_path)

    for _file in os.listdir(goodware):
        _src_path = os.path.join(goodware,_file)
        shutil.copy(_src_path,gw_path)

    directory = pathlib.Path(dir_path)
    # Actually write dir to the archive
    with zipfile.ZipFile(file_path, mode="w") as archive:
        for _file in directory.rglob("*"):
            archive.write(_file, arcname=_file.relative_to(directory))

    # Here we should clean the TMP
    # I'm leaving to debug it

    # Return the zip location
    return file_path
