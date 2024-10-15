# GorillaBot Configuration Extractor

A script to headlessly extract the C2 configuration from a GorillaBot sample.
It will extract the C2 server, port and key. If you add the "--c2" flag it will also connect to the C2 servers and validate the config.
You can run it from the terminal, like this:
```
$ python3 gorillabot_config.py gorillabot_sample.elf
```

Where `gorillabot_sample.elf` is a GorillaBot sample, such as [d50acb9b20222c4e4a616a2ccc095eec2780141da7d4264a5ba2f82cae9c4670](https://www.virustotal.com/gui/file/d50acb9b20222c4e4a616a2ccc095eec2780141da7d4264a5ba2f82cae9c4670/detection).

## Output

```
INFO:gorillabot-config:Loaded sample "x86_32.nn"
INFO:gorillabot-config:Finding main function...
INFO:gorillabot-config:Found main function 0x8051500
INFO:gorillabot-config:Finding config setup function...
INFO:gorillabot-config:Found config function 0x8054480
INFO:gorillabot-config:String value: "/bin/busybox"
INFO:gorillabot-config:String value: "GOLDFISHGANG"
...
INFO:gorillabot-config:String value: "/proc/self/exe"
INFO:gorillabot-config:String value: "UPX!"
INFO:gorillabot-config:Finding C2 connect function...
INFO:gorillabot-config:C2 server: 154.216.19.139
INFO:gorillabot-config:C2 server: 193.143.1.59
INFO:gorillabot-config:C2 server: 94.156.177.61
INFO:gorillabot-config:C2 server: 185.170.144.84
INFO:gorillabot-config:C2 port: 38242
INFO:gorillabot-config:Found C2 connect function 0x804eaa0
INFO:gorillabot-config:Finding C2 connect function...
INFO:gorillabot-config:Found C2 key: "n5F6gLzQwE9kT7pR8jV0xYcA3u2PzM8b"
INFO:gorillabot-config:Found C2 loop function 0x8050980
```
