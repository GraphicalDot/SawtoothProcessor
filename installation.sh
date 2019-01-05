

sudo apt-get install python3-dev
sudo apt-get install libffi-dev
sudo apt-get install libsystemd-dev
export LC_ALL="en_US.UTF-8"
export LC_CTYPE="en_US.UTF-8"


sudo apt install libcurl4-openssl-dev libssl-dev
sudo apt-get update &&
sudo apt-get install -q -y \
     alien \
     autoconf \
     automake \
     build-essential \
     cmake \
     libcurl4-openssl-dev \
     libprotobuf-dev \
     libssl-dev \
     libtool \
     libxml2-dev \
     ocaml \
     pkg-config \
     protobuf-compiler \
     python \
     unzip \
     uuid-dev \
     wget

mkdir ~/sgx && cd ~/sgx
wget https://download.01.org/intel-sgx/linux-2.0/sgx_linux_x64_driver_eb61a95.bin
chmod +x sgx_linux_x64_driver_eb61a95.bin
sudo ./sgx_linux_x64_driver_eb61a95.bin

wget http://registrationcenter-download.intel.com/akdlm/irc_nas/11414/iclsClient-1.45.449.12-1.x86_64.rpm
sudo alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm
sudo dpkg -i iclsclient_1.45.449.12-2_amd64.deb

wget https://github.com/01org/dynamic-application-loader-host-interface/archive/master.zip -O jhi-master.zip
unzip jhi-master.zip && cd dynamic-application-loader-host-interface-master
cmake .
make
sudo make install
sudo systemctl enable jhi



cd ~/sgx
$ wget https://download.01.org/intel-sgx/linux-2.0/sgx_linux_ubuntu16.04.1_x64_psw_2.0.100.40950.bin
$ chmod +x sgx_linux_ubuntu16.04.1_x64_psw_2.0.100.40950.bin
$ sudo ./sgx_linux_ubuntu16.04.1_x64_psw_2.0.100.40950.bin


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
