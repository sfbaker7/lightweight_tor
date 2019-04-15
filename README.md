# lightweight_tor
A light weight implementation of "tor". Use relay nodes hosted on Duke VMs to anonymize your browsing.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
You'll need the following to successfully install and run this project:
```
Python version >= 3.0
```

### Installing

1. Clone this repository and cd into it
```
git clone git@github.com:sfbaker7/lightweight_tor.git
cd lightweight_tor
```

2. Create a virtual environment for our project
```
# create a virtual env called "dev"
python3 -m venv dev

# activate our virtual environment
# note: you'll need to activate virtual env in every terminal / tmux tab
source dev/bin/activate
```

3. Install dependencies in our virtual environment
```
pip install -r requirements.txt
```
