# Performing IEC-61850 GOOSE Attacks with Raw Sockets in C.

This is only on linux at the moment, although windows may come later if I feel like learning winsock. Currently, the packet information is hard coded, but I plan to accept parameters in the future for better scripting. I will also plan to add a sniffing function to accurately imitate the replay attack. For now, that is hard coded as well. Future plans may add a GUI for easier interfacing, but that may cause issues for higher traffic attacks on hardware constrained devices such as the Raspberry Pi. 

## Running the Script
Tested working with GCC, although I don't think anything in here is gcc specific (could be wrong). To get reliable results on the Raspberry Pi, I booted without Xorg, disabled Bluetooth and WiFi, and ran at a higher priority. This only seems necessary at data rates higher than 70 Mbps with small packet (125 bytes was the tested length) <br/>
`
sudo nice -n 18 ./raw_sock_goose.o param1 param2 param3
`

*Param 1*: Attack Traffic in Mbps reliably controls traffic from 1-120 Mbps<br/>
Optional: Default 50 Mbps
  
*Param 2*: Length of attack in seconds<br/>
Optional: Default 20 seconds
  
*Param 3*: StNum attack flag<br/>
Optional: Default True
