

sudo -u sawtooth sawtooth-rest-api -v -B 0.0.0.0:8008
sudo -u sawtooth settings-tp -v
sawset proposal create sawtooth.validator.transaction_families='[{"family": "intkey", "version": "1.0"}, {"family":"sawtooth_settings", "version":"1.0"}]'
sudo -u sawtooth sawtooth-validator -vv

