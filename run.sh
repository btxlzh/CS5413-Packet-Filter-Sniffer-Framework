rmmod sniffer_mod 
insmod ./sniffer_mod.ko
./sniffer_control --mode enable --dst_ip localhost --dst_port 4000  
./sniffer_control --mode enable --src_ip fireless.cs.cornell.edu --src_port 80 --action capture 
