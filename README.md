## Information

This tools for multiple IPv4 scanning

<p align="left">
<img src="img/multiple_ipscanv3.png">
</p>

#### Installing Tools
```
git clone https://github.com/anggrdwjy/multiple-ipscan.git
cd multiple-ipscan
chmod +x multiple_ipscan.py
python3 multiple_ipscan.py --help
```

#### Fiture Tools
```
# help
python3 mutliple_ipscan.py --help

# basic
python3 multiple_ipscan.py 192.168.1.0/24

# multiple scanning ipv4 + ipv6 + export
python3 multiple_ipscan.py 192.168.1.1,fd00::1,10.0.0.1-10.0.0.20,2001:db8::1-2001:db8::ff -t 1 --jobs 100 --csv hasil.csv --json hasil.json

# sorting only "up" and export csv or json
python3 multiple_ipscan.py fd00::/120 --up-only --no-color --no-banner --csv up.csv --json up.json

# timeout 2s, max 1000 IP target
python3 multiple_ipscan.py 10.0.0.0/16 --max-ips 1000 --jobs 200
```

## Support

* [:octocat: Follow me on GitHub](https://github.com/anggrdwjy)
* [🔔 Subscribe me on Youtube](https://www.youtube.com/@anggarda.wijaya)
