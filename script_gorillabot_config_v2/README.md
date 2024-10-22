# GorillaBot Configuration Extractor v2

Another script to automatically process GorillaBot samples to extract C2 configuration.
This version combines [Binary Ninja](https://binary.ninja) with [Qiling](https://qiling.io)
to extract the configuration in a more robust way.

## GorillaBot

The GorillaBot malware will first iterate through a list of encrypted C2-servers,
decrypt them with a modified XTEA algorithm (delta is non-standard) and try to connect to it.
If it suceeds it will proceed to authenticate against the server,
otherwise it will try the next server in the list.
The authentication proceeds by sending a single byte with the value 0x01 to the server.
The server will reply with four random bytes, which we can call the server seed.
Then the malware will decrypt a 32 byte key, again using the XTEA variant, append it to the seed bytes,
calculate the SHA256 hash of this 36 byte value and send it to the server.

## Configuration Extraction

To extract the C2 servers, we emulate the the c2_connect() function with the relevant socket syscalls hooked.
Importantly we hook sys_connect to log the server and port, and getsockopt to report a connection failure
which will cause the next server to be tried. Once we see a repeat, we stop.

To extract the C2 key, we first emulate the c2_connect() function and claim the connection succeeded.
Then we hook send and recv to claim that the data was sent and then return a fake server seed.
We can then use memory tracing to record where this server seed gets written and
trace the 32 bytes that get written adjacent to that value. This is then the key.

## Scope and Limitations

It currently works with x86, x86-64, MIPS and MIPSel samples.
ARM could be supported but the samples I have looked at structures the 
syscalls differently which trips up the way I'm finding the c2_connect() function.
Finally, it is also possible to connect to the C2 server to validate the config but
this is currently not implemented.

Possible improvements:

- Support auto-finding C2 functions for ARM (syscalls are inlined differently)
- Validate against C2

## Usage

Requirements can be found in [requirements.txt]
The script supports the following options:

```
$ python3 gorillabot_config_v2.py --help
Usage: gorillabot_config_v2.py [OPTIONS]

Options:
  -s, --sample TEXT      Sample to analyze  [required]
  --addr-c2connect TEXT  Address of C2 connect function
  --addr-c2loop TEXT     Address of C2 loop function
  --connect              Connect to C2 server to validate config
  --help                 Show this message and exit.
```

To run a full analysis, simply provide the path to a sample:

```
$ python3 gorillabot_config_v2.py -s samples/x86_32.nn
INFO:gorillabot-extractor:Finding syscall functions...
INFO:gorillabot-extractor:Found 13 syscalls of interest
INFO:gorillabot-extractor:Finding C2 connect function...
INFO:gorillabot-extractor:Found C2 connect function at 0x804eaa0
INFO:gorillabot-extractor:Finding C2 loop function...
INFO:gorillabot-extractor:Found C2 loop function at 0x8050980
INFO:gorillabot-extractor:C2 connect function at 0x804eaa0
INFO:gorillabot-extractor:C2 loop function at 0x8050980
INFO:gorillabot-extractor:Extracting C2 servers...
INFO:gorillabot-extractor:1: 154.216.19.139:38242
INFO:gorillabot-extractor:2: 193.143.1.59:38242
INFO:gorillabot-extractor:3: 94.156.177.61:38242
INFO:gorillabot-extractor:4: 185.170.144.84:38242
INFO:gorillabot-extractor:All 4 C2 servers extracted
INFO:gorillabot-extractor:Extracting C2 key...
INFO:gorillabot-extractor:Key found: 3646356e517a4c676b3945775270375430566a38416359785032753362384d7a
{"key": "6F5nQzLgk9EwRp7T0Vj8AcYxP2u3b8Mz", "c2_servers": ["154.216.19.139:38242", "185.170.144.84:38242", "193.143.1.59:38242", "94.156.177.61:38242"]}
```

To perform only the extraction by manually providing the addresses of the C2 functions, run it like this:

```
$ python3 gorillabot_config_v2.py -s samples/x86_64.nn --addr-c2connect 0x4075a0 --addr-c2loop 0x4080b0
INFO:gorillabot-extractor:C2 connect function at 0x4075a0
INFO:gorillabot-extractor:C2 loop function at 0x4080b0
INFO:gorillabot-extractor:Extracting C2 servers...
INFO:gorillabot-extractor:1: 154.216.19.139:38242
INFO:gorillabot-extractor:2: 193.143.1.59:38242
INFO:gorillabot-extractor:3: 94.156.177.61:38242
INFO:gorillabot-extractor:4: 185.170.144.84:38242
INFO:gorillabot-extractor:All 4 C2 servers extracted
INFO:gorillabot-extractor:Extracting C2 key...
INFO:gorillabot-extractor:Key found: 3646356e517a4c676b3945775270375430566a38416359785032753362384d7a
{"key": "6F5nQzLgk9EwRp7T0Vj8AcYxP2u3b8Mz", "c2_servers": ["154.216.19.139:38242", "185.170.144.84:38242", "94.156.177.61:38242", "193.143.1.59:38242"]}
```
