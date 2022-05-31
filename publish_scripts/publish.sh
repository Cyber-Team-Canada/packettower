#!/usr/bin/sh

# this is a quick script to generate a virtual environment that can be quickly
# set up using `source packettower_env/bin/activate`

# get working directory, if not in `packettower`, then exit.
IFS='/'
read -ra currfolder <<< $PWD

if [ "${currfolder[-1]}" != "packettower" ]; then
  echo "please go to the root path of the repository (./packettower)"
  echo "in ${currfolder[-1]}"
  exit 1
fi

# remove existing virtual environment
rm -rd packettower_env

# generate new virtual environment
python3 -m venv packettower_env

# quickly use virtual environment to install necessary packages
source packettower_env/bin/activate
if [[ -z $VIRTUAL_ENV ]]; then
  echo 'could not set venv :('
fi

echo "sucessfully entered venv: \($VIRTUAL_ENV)"
pip3 install -r requirements.txt
deactivate

cp ./packettower.py ./packettower_env/bin/packettower
