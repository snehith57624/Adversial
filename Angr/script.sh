#git clone https://github.com/angr/angr-dev.git
cp Dockerfile angr-dev/
cp setup.sh angr-dev/
cp server.py angr-dev/
cp -r adapters angr-dev/
docker build -t angr angr-dev
