#!/bin/bash


sudo rm -rf /var/lib/sawtooth/
sawset genesis
sudo mkdir -p /var/lib/sawtooth
sudo chown -R sawtooth:sawtooth /var/lib/sawtooth
sudo -u sawtooth sawadm genesis config-genesis.batch
sudo -u sawtooth sawtooth-validator -vv --bind 0.0.0.0:4004  --scheduler parallel
