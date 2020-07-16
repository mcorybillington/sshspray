#sshspray

A multithreaded, queued SSH key and/or password spraying tool.

`sshspray.py` works against a list of hostnames, ip addresses, or CIDR subnet ranges.
You can specify either a keyfile, password, or both. If the keyfile is encrypted, you
can pass the passphrase on the command line, or you can wait to be prompted to enter
it securely. You may pass the password on the command line as well, or if you don't
provide a key or password, you will be prompted for a password.

One file for easy `wget`/`curl`

```
usage: sshspray.py [-h] [-q [QUEUE_SIZE]] [-k HOST_KEY_FILE] -u USER [-s PASSPHRASE] [-i KEY_FILE] [-p PASSWORD] [-P PORT] [-v] -t TARGET_LIST [-w [WAIT]]

optional arguments:
  -h, --help            show this help message and exit
  -q [QUEUE_SIZE], --queue-size [QUEUE_SIZE]
  -k HOST_KEY_FILE, --host-key-file HOST_KEY_FILE
                        Known hosts file (defaults to /dev/null)
  -u USER, --user USER  Username for ssh connection
  -s PASSPHRASE, --passphrase PASSPHRASE
                        Passphrase to unlock private key file
  -i KEY_FILE, --key-file KEY_FILE
                        Path to the private key to test against targets
  -p PASSWORD, --password PASSWORD
                        Password to test against targets
  -P PORT, --port PORT  Port to connect on
  -v, --verbose         Show failures. Use '-vv-' to show reasons for failure
  -t TARGET_LIST, --target-list TARGET_LIST
                        List of hosts to test(hostname, ip, and/or CIDR)
  -w [WAIT], --wait [WAIT]
                        Timeout for each connection in seconds
```
####Author
M. Cory Billington
