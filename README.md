# ping-flood
Counter attacking Ping Flood attack with IP Spoofing and DDoS.

## System requirements

- [VirtualBox](https://www.virtualbox.org/)
- [Vagrant](https://www.vagrantup.com/)

## Setup

Build the `corevm` virtual machine by:

```bash
$ vagrant up
...
```

It's gonna take few minutes if you're running it for the first time. When it's done, just check the virtual machine status by:

```bash
$ vagrant status
...
corevm                    running (virtualbox)
...
```

## Launching

If `corevm` virtual machine isn't running, just follow the steps on the [Setup section](#setup). Otherwise, just ssh to it and open the core application.

```bash
$ vagrant ssh
vagrant@corevm:~$ sudo /etc/init.d/core-daemon start
starting core-daemon
vagrant@corevm:~$ core-gui
Connecting to "core-daemon" (127.0.0.1:4038)...connected.
```

## Exiting

If you're running `core-gui`, then your terminal window should be looking like this:


```bash
vagrant@corevm:~$ core-gui
Connecting to "core-daemon" (127.0.0.1:4038)...connected.
```

On `core-gui` window click on File and then click on Quit. On the terminal window, it should display the connection to the core-daemon is closed. Now you should be able to run `exit` inside `corevm` and then halt the virtual machine.

```bash
Connection to "core-daemon" (127.0.0.1:4038) closed.
vagrant@corevm:~$ exit
$ vagrant halt
```

To be sure if `corevm` virtual machine is down just check its status by:

```bash
$ vagrant status
...
corevm                    poweroff (virtualbox)
...
```

## Loading topology

On `core-gui` window click on File, then click on Open and then navigate to `/vagrant` directory and select `topology.imn`/`topology.xml` file.

## Simulation

Run the simulation, open the bash on the desired hosts and pick one of them as the attacker and another as the target. On the target host run the python script by:

```bash
$ cd /vagrant
$ python3 counter_attack_ping_flood.py
```

Except for the attacker host, open the bash on the desired hosts and run a simple ping command to the IP address of the target host for a few seconds. The running python script on the target host must have captured the hosts IP address from the ICMP packets sent by the ping. Their IP addresses must have been logged on the target host bash window as follows:

```
ICMP IP src: X.X.X.X
```

On the attacker bash window you need to run a ping flood with an interval threshold less than 0.01 seconds. You can just run a ping flood that will run for 5 seconds without specifying an interval by:

```bash
$ ping -w 5 -f -q X.X.X.X
```

Or you can specify an interval of 0.005 seconds with:

```bash
$ ping -w 5 -f -q -i 0.005 X.X.X.X
```

If you specify an interval equal or greater than 0.01 seconds the ping flood won't be counter attacked. If you want to send a specific amount of packets (500 for example) instead of setting a timeout in seconds, you can replace `-w 5` by `-c 500`.

```bash
$ ping -c 500 -f -q -i 0.005 X.X.X.X
```

On the target bash window it should be displayed something like:

```
Attack Detected!
Flood interval: 0:00:00.005
Counter attacking...
Sending ICMP src: X.X.X.X dst: Y.Y.Y.Y
Sending ICMP src: X.X.X.X dst: Z.Z.Z.Z
...
```

## Implementation

The Python script sniffs all packets coming through `eth0` network interface and filters for further processing only IP packets matching the following requirements:

- Its protocol must be the ICMP protocol
- Its source MAC address must be different from the host's (to process only incoming packets).

For each filtered packet, the source IP address is stored (as key) into a dictionary a current time date object (as value) if it's the first received packet from that same IP address. If it's not the first packet, then it's calculated the time delta between now and the previous stored date object. If it's less than the threshold (0.01 seconds) then it's identified as a ping flood attack and a counter attack will be executed.

The counter attack basically is a DDoS attack by IP Spoofing the target address of a ICMP packet. For each received ICMP packet from the attacker (with interval smaller than the threshold), it will be generated new ICMP packets for each stored IP address (different from the attacker's) as destiny IP with the attacker's IP address as source IP. Thus each online host will start to ICMP Echo Reply the attacker like a DDoS attack flooding the attacker back.

## Demo

[![Simulation Video](https://img.youtube.com/vi/8thg2d5hvpw/0.jpg)](https://www.youtube.com/watch?v=8thg2d5hvpw)
