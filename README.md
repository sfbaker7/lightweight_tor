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

## Development
For the purposes of demonstration, we've configured all servers to be hosted on localhost such that you won't need multiple machines to test `lightweight_tor`. There are 5 servers that we need to get up and running in order to simulate the onion routing protocol:
1. `directory.py`
2. `relay_server.py`
3. `relay_server1.py`,
4. `relay_server2.py`,
5. `client_server.py`

You need to start up your `directory.py` server first before starting up any of the other servers, and start them in different terminal/tmux sessions in order of:
`directory -> relay servers -> client_server`.

When you finally run `./client_server.py <some_domain_name>`, assuming the other servers are up and running, it'll trigger a request to our onion network using the `<some_domain_name>` that was entered. For example, `./client_server.py https://facebook.com` will make a request via `lightweight_tor`, using the onion network, to `facebook.com`.

