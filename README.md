# ms17_010_scanner

This simple SMB vulnerability MS17-010 scanner is developed to help security professionals to quickly check if a computer is vulnerable
to MS17-010 vulnerability.

What this scanner will do:
* Connect to the target computer using port 445.
* Send "SMB_COM_NEGOTIATE" and "SMB_COM_SESSION_SETUP_ANDX" packets to establish an SMB session.
* Connect to the IPC$ share on the target computer by sending "SMB_COM_TREE_CONNECT_ANDX" packet with TreeID set
to \\<ip_address>\IPC$ and UserID set to the value returned by the server in the previous response.
* Check for MS17-010 vulnerability by sending an "SMB_COM_TRANSACTION" packet, containing PeekNamedPipe subcommand set to FileID = 0.
* Check for the error response code 0xC0000205 (STATUS_INSUFF_SERVER_RESOURCES). If the code is found that means the target computer's Windows operating system is vulnerable to MS17-010.

## Downloads
ms17_010_scanner Windows executable file can be downloaded here
https://github.com/ch4meleon/ms17_010_scanner/releases/download/v1.0/ms17_010_scanner.exe

## Usage
* Scan a target computer
```
python ms17_010_scanner.py -t 10.0.0.3
or
ms17_010_scanner.exe -t 10.0.0.3
```

* Scan a list of computers
```
python ms17_010_scanner.py -l hosts.txt
or
ms17_010_scanner.exe -l hosts.txt
```

## Screenshots
<img align="center" src="./1.PNG" alt="Screenshot #1" />

## Contact
ch4meleon@protonmail.com
