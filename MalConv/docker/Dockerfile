FROM python:3.9
WORKDIR /ramen
RUN git clone https://github.com/snehith57624/Adversarial-PE-Strategies
RUN pip install -r /ramen/secml_malware/requirements.txt
RUN pip install torch torchvision
RUN pip install -e /ramen/secml_malware
COPY requirements.txt /ramen/secml_malware/requirements.txt
RUN pip install -r /ramen/secml_malware/requirements.txt
EXPOSE 8080
COPY adapters /ramen/adapters/
COPY server.py /ramen/
COPY secml_malware/utils/pe_operations.py /ramen/secml_malware/secml_malware/utils/pe_operations.py
