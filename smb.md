# SMB Stuff 

## File Transfer 
The SMB Server will be hosted on your linux host and you will be able to transfer both ways (Download/Upload) --  just inverse the order between the source file and the destination file.
```bash
# On linux
sudo python3 /opt/impacket/examples/smbserver.py SHARE_NAME SOURCE_DIRECTORY -smb2support

# On Windows
copy “\\IP\SHARE_NAME\SOURCE_FILE” “DESTINATION_FILE”
```
