

sudo apt-get install python3-dev
sudo apt-get install libffi-dev
export LC_ALL="en_US.UTF-8"
export LC_CTYPE="en_US.UTF-8"




sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD
sudo add-apt-repository 'deb http://repo.sawtooth.me/ubuntu/1.0/stable xenial universe'
sudo apt-get update 
sudo apt-get install sawtooth 

sawtooth keygen
sawset genesis
sudo -u sawtooth sawadm genesis config-genesis.batch

#To start a validator that listens locally on the default ports, run the following commands:
sudo sawadm keygen




##requied to install pycurl
sudo apt-get install autoconf automake libtool curl make g++ unzip
