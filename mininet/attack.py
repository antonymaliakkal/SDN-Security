from scapy.all import *
import time



class Attack():

    def DoS(self, net, hostname):
        h = net.get(hostname)
        attack_command = "hping3 -c 1000 -S -p 80 --faster 10.0.0.2 &"
        attack_process = h.cmd(attack_command)
        print('ended')
        print(attack_process)

    def prob(self, net, hostname):
        h = net.get(hostname)
        attack_command = "nmap  10.0.0.2  &"
        attack_process = h.cmd(attack_command)
        print('ended')
        print(attack_process)

    def norm(self, net, hostname):
        h = net.get(hostname)
        attack_command = "hping3 -c 10 -S -p 80  10.0.0.2 &"
        attack_process = h.cmd(attack_command)
        print('ended')
        print(attack_process)