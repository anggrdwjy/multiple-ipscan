## Information

This tools for multiple IPv4 scanning

<p align="left">
<img src="img/multiple_ipscanv3.png">
</p>

#### Installing Tools
```
root@server1:~# git clone https://github.com/anggrdwjy/multiple-ipscan.git
root@server1:~# cd multiple-ipscan
root@server1:~multiple-ipscan# chmod +x multiple_ipscan.py
root@server1:~multiple-ipscan# python3 multiple_ipscan.py --help
```

#### Fiture Tools
```
# help
python3 ipscan.py --help

# basic
python3 ipscan.py 192.168.1.0/24

# campur v4 + v6 + export
python3 ipscan.py 192.168.1.1,fd00::1,10.0.0.1-10.0.0.20,2001:db8::1-2001:db8::ff -t 1 --jobs 100 --csv hasil.csv --json hasil.json

# cuma yang UP aja, tanpa warna, tanpa banner (buat di cron)
python3 ipscan.py fd00::/120 --up-only --no-color --no-banner --csv up.csv --json up.json

# timeout 2 detik, max 1000 IP per target (biar aman)
python3 ipscan.py 10.0.0.0/16 --max-ips 1000 --jobs 200
```

## Support

* [:octocat: Follow me on GitHub](https://github.com/anggrdwjy)
* [🔔 Subscribe me on Youtube](https://www.youtube.com/@anggarda.wijaya)
