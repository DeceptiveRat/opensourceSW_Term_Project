# 1. Packet sniffer
## 1-1 Description
On unswitched networks, Ethernet packets pass through every device on the network. This means any device can pick up packets that aren't meant for itself. This is called packet sniffing. This program allows you to do just that. 
Currently, it can capture packets, verify the checksum of UDP and TCP packets, and save them to a file. More features, such as identifying DNS traffic are being added.

## 1-2 Installation
git clone the repository into your desktop environment and you are good to go!
(Note: originally developed for Linux Operating Systems. Probably will not work in Windows environments)

## 1-3 Usage
navigate to the "packet_sniffer" directory and 
```bash 
sudo ./decode_sniff
```
to start the program. 

![Image display failed](https://github.com/DeceptiveRat/opensourceSW_Term_Project/edit/main/packet_sniffer/chooseInterface.png?raw=true)
Choose the interface you want to use.

![Image display failed]([http://url/to/img.png](https://github.com/DeceptiveRat/opensourceSW_Term_Project/edit/main/packet_sniffer/successMessage.png?raw=true)
If it worked properly, you should get the success message like the picture.

![Image display failed]([http://url/to/img.png](https://github.com/DeceptiveRat/opensourceSW_Term_Project/edit/main/packet_sniffer/result.png?raw=true)
![Image display failed]([http://url/to/img.png](https://github.com/DeceptiveRat/opensourceSW_Term_Project/edit/main/packet_sniffer/packet.png?raw=true)
If you open the new txt file, the packets that have been caught are displayed there.

## 1-4 License 
This project is licensed under the GNU General Public License v3. See the [LICENSE](packet_sniffer/LICENSE) file for details.

## 1-5 Acknowledgements
This project was inspired by concepts and examples presented in *Hacking: The Art of Exploitation (2nd Edition, 2008)* by Jon Erickson. 

## 2. OTHER PROJECTS GO HERE

