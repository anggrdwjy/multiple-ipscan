## Information

<p align="left">
<img src="img/multiple_ipscanv3.png">
</p>

#### Installing
```
git clone https://github.com/anggrdwjy/multiple-ipscan.git
cd multiple-ipscan
chmod +x multiple_ipscan.py
python3 multiple_ipscan.py --help
```

#### Features
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

#### Helping Tools
```
root@labstack:~# python3 multiple_ipscan.py --help
usage: Ipscan.py [-h] [-t TIMEOUT] [-m {all,up_only}] [--max-ips MAX_IPS] [--jobs JOBS] [--csv CSV_FILE] [--json JSON_FILE] [--up-only] [--no-color] [--no-banner] target

Advanced Hybrid IPv4/IPv6 Scanner - Python Version

positional arguments:
  target                Target IP/CIDR/Range, pisah koma untuk multiple. Bisa campur v4 & v6. Contoh: 192.168.1.0/24,fd00::/120

options:
  -h, --help            show this help message and exit
  -t, --timeout TIMEOUT
                        Timeout ping dalam detik (default: 1)
  -m, --mode {all,up_only}
                        Mode tampil: all (UP & DOWN) atau up_only (default: all)
  --max-ips MAX_IPS     Maksimal IP per target (anti bom /64, default: 65536)
  --jobs JOBS           Jumlah thread bersamaan (default: 100, bash versi 80)
  --csv CSV_FILE        Export hasil ke CSV
  --json JSON_FILE      Export hasil ke JSON
  --up-only             Shortcut untuk --mode up_only
  --no-color            Matikan warna
  --no-banner           Sembunyikan banner ASCII

Contoh penggunaan:
  multiple_ipscan.py 192.168.1.0/24
  multiple_ipscan.py fd00::/120 --csv hasil.csv --json hasil.json
  multiple_ipscan.py 192.168.1.1,fd00::1,10.0.0.1-10.0.0.20 -t 1 --jobs 100 --up-only
  multiple_ipscan.py 8.8.8.8,1.1.1.1 --csv google_dns.csv --json google_dns.json --all
        
root@labstack:~# 
```

## Support

* [:octocat: Follow me on GitHub](https://github.com/anggrdwjy)
* [🔔 Subscribe me on Youtube](https://www.youtube.com/@anggarda.wijaya)
