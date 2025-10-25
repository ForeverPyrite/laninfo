# laninfo
Simple, reasonably paced Python library for discovering information about a host's private network.

## TODO
As of now, I pretty much just stole the code for [networkscan](https://github.com/ericorain/python_scripts/tree/master/networkscan), removed the bad global variables, added typing, and had an AI do some documentation.

I want this to preferably be able to find the LAN itself, netmask and all.

- [ ] Automatic LAN discovery
- [ ] Multiple networks at once
- [ ] Perhaps add the ability to scan on a specific port (unless [python3-nmap](https://github.com/nmmapper/python3-nmap) already has a simple API for it)
- [ ] IPv6
  - How could this even be done? Maybe beg for NAs? Not sure.
  - Right now the code will actually create a generator for IPv6Network's hosts, so that should probably be handled because that would be INSANE
- [ ] Split into library and script, kinda like Rust ykyk. 
- [ ] Publish to PyPI if I'm happy with it, cause why not
