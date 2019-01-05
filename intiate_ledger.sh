sudo sawadm keygen

sudo  mkdir ~/.sawtooth
sudo chown -R sawtooth:sawtooth ~/.sawtooth/
 sudo -u sawtooth  sawtooth keygen --key-dir ~/.sawtooth
 sawadm genesis config-genesis.batch
