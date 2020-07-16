from paramiko import SSHClient, AutoAddPolicy, RSAKey, DSSKey, ECDSAKey, Ed25519Key
from paramiko.ssh_exception import SSHException, PasswordRequiredException
from paramiko.hostkeys import HostKeys
from paramiko.util import log_to_file
from ipaddress import IPv4Network
from threading import Thread
from argparse import ArgumentParser
from getpass import getpass
from queue import Queue
from sys import exit
from re import compile
from os import devnull

from os.path import isfile


class Message:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def success():
        return f"{Message.OKGREEN}[SUCCESS]:{Message.ENDC}"

    @staticmethod
    def fail():
        return f"{Message.FAIL}[FAILED]:{Message.ENDC}"

    @staticmethod
    def warning():
        return f"{Message.WARNING}[WARNING]:{Message.ENDC}"

    @staticmethod
    def info():
        return f"{Message.WARNING}[INFO]:{Message.ENDC}"

    @staticmethod
    def keyboard_interrupt_exit_msg():
        print(Message.warning(), "Keyboard Interrupt Detected, exiting...")


class KeyChecks:
    KEY_TYPES = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]

    def __init__(self, key_file, passphrase):
        self.key_file = key_file
        self.passphrase = passphrase
        self.key_file_exists = True
        self.valid_key = False
        self.is_encrypted = False

    def check_key_file_exists(self):
        if not self.key_file:
            print(Message.info(), "No key file specified")
            self.key_file_exists = False
            return
        if not isfile(self.key_file):
            self.key_file_exists = False
            print(Message.info(), "Key {keyfile} does not exist.".format(keyfile=self.key_file))

    def decrypt_key(self):
        if not self.passphrase:
            try:
                prompt_message = "Enter passphrase for key '{filename}': ".format(filename=self.key_file)
                self.passphrase = getpass(prompt=prompt_message)
            except KeyboardInterrupt:
                Message.keyboard_interrupt_exit_msg()
                exit(1)
        for pk in KeyChecks.KEY_TYPES:
            try:
                pk.from_private_key_file(self.key_file, self.passphrase)
                self.valid_key = True
            except Exception as e:
                if isinstance(e, SSHException):
                    pass
                else:
                    raise e

    def check_key(self):
        for pk in KeyChecks.KEY_TYPES:
            try:
                pk.from_private_key_file(self.key_file)
                self.valid_key = True
            except Exception as e:
                if isinstance(e, PasswordRequiredException):
                    self.is_encrypted = True
                    break
                elif isinstance(e, SSHException) or isinstance(e, IOError):
                    pass
                else:
                    raise e
        if self.is_encrypted:
            self.decrypt_key()
        if not self.valid_key:
            print(Message.warning(), "Invalid key file: {filename}".format(filename=self.key_file))

    def do_key_checks(self):
        self.check_key_file_exists()
        if not self.key_file_exists:
            return
        self.check_key()


class Sprayer:
    def __init__(self, queue, username, key_file, password, passphrase,
                 host_key_file, port, timeout, target_list, verbosity):
        self.queue = queue
        self.username = username
        self.key_file = key_file
        self.password = password
        self.passphrase = passphrase
        self.host_key_file = host_key_file
        self.port = port
        self.timeout = timeout
        self.verbose = verbosity
        self.target_list = target_list

    def do_work(self):
        while True:
            ip = self.queue.get()
            self.try_auth(ip)
            self.queue.task_done()

    def conn_params(self, ip):
        return {
            "hostname": ip,
            "username": self.username,
            "password": self.password,
            "key_filename": self.key_file,
            "timeout": self.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

    def try_auth(self, ip):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        conn_params = self.conn_params(ip)
        try:
            ssh.connect(**conn_params)
            ssh.close()

            print(Message.success(), ip)
        except Exception as e:
            if not self.verbose:
                pass
            else:
                output = [Message.fail(), ip, e]
                print(*output[0:self.verbose+1])

    def run(self) -> None:
        print(Message.info(), "Running against {hostcount} hosts...".format(hostcount=len(self.target_list)))
        for i in range(self.queue.maxsize):
            t = Thread(target=self.do_work)
            t.daemon = True
            t.start()
        try:
            for rhost in self.target_list:
                self.queue.put(rhost.strip())
            self.queue.join()
        except Exception as e:
            if isinstance(e, KeyboardInterrupt):
                Message.keyboard_interrupt_exit_msg()
                exit(1)
            else:
                raise e


def arg_parse():
    parser = ArgumentParser(description="Multithreaded, queued SSH key and/or password spraying tool by M. Cory Billington")
    parser.add_argument("-q", "--queue-size", nargs='?', default=200, type=int)
    parser.add_argument("-k", "--host-key-file", default=devnull, help="Known hosts file (defaults to /dev/null)")
    parser.add_argument("-u", "--user", required=True, help="Username for ssh connection")
    parser.add_argument("-s", "--passphrase", default=None, help="Passphrase to unlock private key file")
    parser.add_argument("-i", "--key-file", help="Path to the private key to test against targets")
    parser.add_argument("-p", "--password", help="Password to test against targets")
    parser.add_argument("-P", "--port", default=22, help="Port to connect on")
    parser.add_argument("-v", "--verbose", action='count', default=0, help="Show failures. Use '-vv-' to show reasons for failure")
    parser.add_argument("-t", "--target-list", required=True, help="List of hosts to test(hostname, ip, and/or CIDR)")
    parser.add_argument("-w", "--wait", nargs='?', default=1, type=int, help="Timeout for each connection in seconds")
    return parser.parse_args()


def get_host_list(file):
    valid_cidr = compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|1[0-9]|2[0-9]|3[0-2])$')
    try:
        with open(file, 'r') as f:
            rhosts = f.read().splitlines()
    except FileNotFoundError as e:
        raise e

    cidrs = [ip for ip in rhosts if valid_cidr.match(ip)]

    if cidrs:
        for cidr in cidrs:
            ip_range = [str(ip) for ip in IPv4Network(cidr)]
            rhosts.extend(ip_range)
    return list(set(rhosts))


def main():
    args = arg_parse()

    key_check = KeyChecks(args.key_file, args.passphrase)
    key_check.do_key_checks()

    password = args.password
    passphrase = args.passphrase

    if not key_check.valid_key:
        args.key_file = None
        if not password:
            try:
                prompt_message = "{username}'s password: ".format(username=args.user)
                password = getpass(prompt=prompt_message)
            except KeyboardInterrupt:
                Message.keyboard_interrupt_exit_msg()
                exit(1)
            if not password:
                print(Message.fail(), "A password [-p/--password] or valid private keyfile [-t/--target-file] is required")
                exit(1)
        else:
            print(Message.info(), "No keyfile set, using password: {passwd}".format(passwd=args.password))

    if key_check.is_encrypted:
        passphrase = key_check.passphrase

    verbosity = 2 if args.verbose > 2 else args.verbose
    queue = Queue(args.queue_size)
    HostKeys(args.host_key_file)
    log_to_file(devnull)
    targets = get_host_list(args.target_list)
    sprayer = Sprayer(queue=queue,
                      username=args.user,
                      port=args.port,
                      key_file=args.key_file,
                      host_key_file=args.host_key_file,
                      password=password,
                      passphrase=passphrase,
                      timeout=args.wait,
                      verbosity=verbosity,
                      target_list=targets)
    sprayer.run()


if __name__ == "__main__":
    main()
