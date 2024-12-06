# VyOS Clash Script Using Custom Tunnel





## Install

REQUIRES SUPPORT FOR CUSTOM TUNNEL

https://vyos.dev/T6928


### 1. Add support for custom tunnel

```
root@vyos:/home/vyos# ls  /config/utunnels/
clash.yaml
```

clash.yaml
```
type: clash
scripts:
  start: /usr/bin/python3 /config/clash/bin/clashctl.py start {device}
  stop: /usr/bin/python3 /config/clash/bin/clashctl.py stop {device}
  update: /usr/bin/python3 /config/clash/bin/clashctl.py reload {device}
  status: systemctl status clash@{device}
```

### 2. Create custom tunnel

Use `utun0` as example.

``` 
configure
set interfaces utunnel utun0 address '198.18.0.1/16'
set interfaces utunnel utun0 description 'clash tunnel'
set interfaces utunnel utun0 manage-type 'external'
set interfaces utunnel utun0 tunnel-type 'clash'
commit
save
```

Clash program will not be brought up at this point, because the custom tunnel doesn't yet support manage all kind of services.


### 3. Put clashctl.py to /config/clash/bin

Please do this manually, I will provide an installation script in future.

### 4. Install Clash Binary and UI

```
# execute permissions
chmod +x /config/clash/bin/clashctl.py

# install binary and ui
/config/clash/bin/clashctl.py install 

```

### 5. Configure Clash

Create `/config/clash/config/utun0.yaml`

```
# service type
service: clash
# subscription url
subscription: https://some.sub.scrip.tion/url/xxx

```

If you have extra config to extend, add yamls to `/config/clash/config/utun0/`, example:

`/config/clash/config/utun0/99-misc.yaml`

```
external-controller: "0.0.0.0:9090"
secret: "123321"
allow-lan: true
redir-port: 7892
tproxy-port: 7895
mixed-port: 7893
bind-address: "*"
external-ui: "/config/clash/ui"
ipv6: false
```

Current script doesn't support overwriting config like ubnt-clash.


### 6. Run command

``` 
# Restart tunnel
restart utunnel utun0

# Start on boot
systemctl enable clash@utun0

```

Service is managed using systemd, you may need to run `systemctl daemon-reload` manually.



### 7. Start/Stop scripts

pre-up, post-up, post-down scripts are supported, you can create scripts to 

* `/config/clash/config/utun0/scripts/pre-up`
* `/config/clash/config/utun0/scripts/post-up`
* `/config/clash/config/utun0/scripts/post-down`

Make sure you give the right permissions.


Example:

`post-down`
``` 
#!/bin/sh

DEV=utun0

ip route del 198.18.0.0/16 dev $DEV proto kernel scope link src 198.18.0.1
```

`post-up`

``` 
#!/bin/sh

DEV=utun0

ip route delete 198.18.0.0/30 dev $DEV proto kernel scope link src 198.18.0.1

ip route add 198.18.0.0/16 dev $DEV proto kernel scope link src 198.18.0.1
```

## VyOS Commands

```
configure

# create an address group and add 192.168.1.100 as a member 
set firewall group address-group SRC_CLASH address '192.168.1.100'
# create an address group, add router's ip, similar to UBNT's ADDRv4_eth0 but no need to add many rules 
set firewall group address-group ROUTER_IN address '192.168.1.1'
# create an interface group, add router's lan interface 
set firewall group interface-group CLIENT_IN_DEV interface 'eth0'

# nat router's dns port to clash dns 7874
set nat destination rule 5000 description 'Clash UDP port'
set nat destination rule 5000 destination group address-group 'ROUTER_IN'
set nat destination rule 5000 destination port '53'
set nat destination rule 5000 inbound-interface group 'CLIENT_IN_DEV'
set nat destination rule 5000 protocol 'udp'
set nat destination rule 5000 source group address-group 'SRC_CLASH'
set nat destination rule 5000 translation port '7874'

# exclude local traffics or other direct traffics
set nat destination rule 8000 destination group address-group 'ROUTER_IN'
set nat destination rule 8000 exclude
set nat destination rule 8200 destination group network-group 'IP_LAN'
set nat destination rule 8200 exclude
set nat destination rule 8500 destination group network-group 'CHINA_IP'
set nat destination rule 8500 exclude

# nat tcp traffic to clash redir-port 7892
set nat destination rule 9000 description 'Clash TCP Redir'
set nat destination rule 9000 inbound-interface group 'CLIENT_IN_DEV'
set nat destination rule 9000 protocol 'tcp'
set nat destination rule 9000 source group address-group 'SRC_CLASH'
set nat destination rule 9000 translation redirect port '7892'

commit
save

```

TODO:

* Add support of custom NAT chain to VyOS and allow nat jump to custom chain.
* UDP not forwarded yet.


## TODO

