## Forensics: Network Captures (pcap) & Memory
Pcap triage: `tshark -r f.pcap -q -z io,phs` (protocol hierarchy — see what's there), `-q -z conv,tcp` (conversations), `capinfos`.
Extract:
- Follow streams: `tshark -r f -q -z follow,tcp,ascii,0` or Wireshark "Follow TCP/HTTP stream" — creds, commands, flags in plaintext protocols.
- Pull transferred files: `tshark -r f --export-objects http,outdir` (also smb/tftp/imf); `foremost`/`binwalk` on the raw pcap.
- Credentials: `tshark -Y "http.authorization || ftp.request.command==USER || ftp.request.command==PASS"`; `pcredz`; HTTP basic-auth base64; POST bodies (`-Y http.request.method==POST -T fields -e http.file_data`).
- DNS exfil: long/odd subdomain labels (`-Y dns -T fields -e dns.qry.name`) — decode base32/hex from labels.
- USB HID: keystroke pcaps -> map `usb.capdata` bytes to keys (HID usage table).
- TLS: decrypt only with a provided key/`SSLKEYLOGFILE`.
- ICMP/other covert channels: check data fields for smuggled bytes.
Filter cheats: `-Y "http.request"`, `-Y "tcp.port==1337"`, `-T fields -e <field>`.
Memory dumps (Volatility3): `vol -f dump windows.info`; then `windows.pslist`/`pstree`, `windows.cmdline`, `windows.filescan`+`windows.dumpfiles`, `windows.hashdump`, `windows.netscan`, `windows.malfind`, strings/`bulk_extractor`. Linux: `linux.bash` (shell history), `linux.pslist`. Hunt creds, command history, injected code, and the flag in process memory.
