import os
import sys
import shutil
import zipfile

from secml_malware.models import CClassifierEnd2EndMalware, MalConv, End2EndModel
import numpy as np

import torch
import torch.nn as nn

from libauc.optimizers import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau

from sklearn.metrics import mean_squared_error
from secml.array import CArray
import pandas as pd


class MalConvFactory:
    def __init__(self):
        pass

    def train_model(self, mw, gw):
        root = os.path.dirname(
            os.path.dirname(os.path.abspath(sys.modules["secml_malware"].__file__))
        )
        path_mod = os.path.join(root, "secml_malware/data/trained/pretrained_malconv.pth")
        model = MalConv(pretrained_path=path_mod)
        classifier = CClassifierEnd2EndMalware(model=model)
        files_set = [gw, mw]
        label_set = [0.0, 1.0]
        criterion = nn.BCELoss()
        optimizer = Adam(model.parameters(), lr=0.01)
        scheduler = ReduceLROnPlateau(optimizer, patience=3, verbose=True, factor=0.5,
                                      threshold=0.001, min_lr=0.00001, mode='max')
        epochs = 3
        y_pred_list = []
        y_original_list = []
        model.train(True)
        for epoch in range(epochs):
            for i in range(len(files_set)):
                label = label_set[i]
                # label = torch.tensor(label)  # Convert label to a PyTorch tensor
                for _file in files_set[i]:
                    try:
                        f = open(_file, 'rb').read()
                        x = End2EndModel.bytes_to_numpy(f, classifier.get_input_max_length(),
                                                        classifier.get_embedding_value(),
                                                        classifier.get_is_shifting_values())
                        x = np.expand_dims(x, axis=0)
                        x = torch.from_numpy(x)

                        y_pred = model.embedd_and_forward(model.embed(x))
                        label = label.view(y_pred.shape)
                        y_pred_list.append(y_pred.numpy()[0])
                        y_original_list.append(label)
                    except Exception as e:
                        print(e)
                y_pred_list = pd.DataFrame(y_pred_list)
                y_original_list = pd.DataFrame(y_original_list)
                loss = criterion(y_pred_list, y_original_list)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
            model.eval()
            rmse = np.sqrt(mean_squared_error(y_original_list, y_pred_list))
            scheduler.step(rmse)
        return model

    def train_classifier(self, mw, gw):
        model = self.train_model(mw, gw)
        file_path = 'model.pth'
        torch.save(model.state_dict(), file_path)
        net = CClassifierEnd2EndMalware(model=model)
        net.load_pretrained_model(file_path)
        return net


# # For standalone code to run
# def unzip():
#     dir_path = "/Archive/"
#     file_path = "/toucanstrike_webserver/commands/Archive.zip"
#     password = "infected"
#     # if os.path.exists(dir_path):
#     #     shutil.rmtree(dir_path)
#     # if os.path.exists(file_path):
#     #     os.remove(file_path)
#     with zipfile.ZipFile(file_path, 'r') as zip_ref:
#         zip_ref.extractall(dir_path, pwd=password.encode())
#     mw_path = os.path.join(dir_path, "malware/")
#     gw_path = os.path.join(dir_path, "goodware/")
#     mw_list = []
#     for _file in os.listdir(mw_path):
#         mw_list.append(os.path.join(mw_path, _file))
#     gw_list = []
#     for _file in os.listdir(gw_path):
#         gw_list.append(os.path.join(gw_path, _file))
#     return mw_list, gw_list
#
#
# def run():
#     model1 = MalConv()
#     net = CClassifierEnd2EndMalware(model=model1)
#     net.load_pretrained_model()
#     mw, gw = unzip()
#     model2 = MalConvFactory().train_model(mw, gw)
#     file_path = 'model.pth'
#     torch.save(model2.state_dict(), file_path)
#     net2 = CClassifierEnd2EndMalware(model=model2)
#     net2.load_pretrained_model(file_path)
#     for file in mw:
#         f = open(file, 'rb').read()
#         x = End2EndModel.bytes_to_numpy(f, net2.get_input_max_length(), net2.get_embedding_value(),
#                                         net2.get_is_shifting_values())
#         x = CArray(x).atleast_2d()
#         # y = CArray([1])
#         print("Prediction malware by default malconv classifier ", net.predict(x))
#         print("Prediction malware by trained malconv classifier ", net2.predict(x))
#     for file in gw:
#         f = open(file, 'rb').read()
#         x = End2EndModel.bytes_to_numpy(f, net2.get_input_max_length(), net2.get_embedding_value(),
#                                         net2.get_is_shifting_values())
#         x = CArray(x).atleast_2d()
#         # y = CArray([1])
#         print("Prediction goodware by default malconv classifier ", net.predict(x))
#         print("Prediction goodware by trained malconv classifier ", net2.predict(x))
#     # check(model2)
#     # verify(model2)
#
#
# run()
