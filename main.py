#!/usr/bin/env python3
"""
A network scanning tool that uses asynchronous ping operations to discover live hosts
within a specified network or IP address range. It supports outputting results
to the console or saving them to a plain text file.
"""

import sys
import platform
import ipaddress
import asyncio
import logging
from typing import List, Tuple, Any, Optional, Union, Coroutine
import argparse

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


# TODO: See if there is a better way to go about this than passing the command everytime, maybe?
async def ping_coroutine(cmd: str, ip: str) -> Tuple[str, bool]:
    """Sends a single ICMP ping request to an IP address asynchronously.

    This coroutine executes a ping command for a given IP address and
    determines if the host responded. It returns the IP address and a boolean
    indicating whether the ping was successful.

    Args:
        cmd: The complete shell command string to execute (e.g., "ping -c 1 192.168.1.1").
        ip: The IP address being pinged.

    Returns:
        A tuple containing:
            - str: The IP address that was pinged.
            - bool: True if the ping received a reply, False otherwise.
    """
    try:
        # Run the ping shell command.
        # stderr is redirected to PIPE to avoid "Do you want to ping broadcast? Then -b. If not,
        # check your local firewall rules." on Linux systems for broadcast pings.
        running_coroutine = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        # Suspends the current coroutine allowing other tasks to run.
        stdout, stderr = await running_coroutine.communicate()

        # Check if "ttl=" (Time To Live) is present in the ping output, indicating a successful reply.
        if "ttl=" in stdout.decode().lower():
            return ip, True
        else:
            if stderr:
                logger.debug(
                    f"Ping to {ip} failed with error: {stderr.decode().strip()}"
                )
            return ip, False
    except asyncio.CancelledError:
        logger.warning(f"Ping task for {ip} was cancelled.")
        return ip, False
    except Exception as e:
        logger.error(f"An unexpected error occurred while pinging {ip}: {e}")
        return ip, False


async def ping_loop(
    tasks_lists: List[List[Coroutine[Any, Any, Tuple[str, bool]]]],
) -> List[Tuple[str, bool]]:
    """Runs a series of ping coroutines in batches.

    This function iterates through a list of lists of coroutines, starting and
    awaiting completion of each batch of pings. It collects the results from
    each individual ping operation.

    Args:
        tasks_lists: A list of lists, where each inner list contains `ping_coroutine`
                     coroutines to be executed concurrently.

    Returns:
        A list of tuples, where each tuple contains (IP address, ping_success_status).
    """
    all_results: List[Tuple[str, bool]] = []
    for each_task_list in tasks_lists:
        # asyncio.as_completed yields tasks as they complete, allowing for concurrent processing.
        for each_coroutine_result in asyncio.as_completed(each_task_list):
            try:
                ip, found_status = await each_coroutine_result
                all_results.append((ip, found_status))
            except Exception as e:
                logger.error(f"Error awaiting coroutine result in ping_loop: {e}")
    return all_results


class Networkscan:
    """Manages the network scanning process, including IP validation, ping execution, and result saving.

    This class encapsulates the logic for defining a network, scanning it for
    live hosts using asynchronous pings, and optionally saving the results
    to various file formats.
    """

    # TypeAlias for IPv4 and IPv6 networks
    # WARN: This doesn't even make sense rn
    Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

    # Type hints for class attributes
    hosts_found: int
    list_of_hosts_found: List[str]
    filename: str
    network: Network
    network_host_count: int
    one_ping_param: str

    def __init__(self, ip_and_prefix: str):
        """Initializes the Networkscan object with the target network.

        Args:
            ip_and_prefix: A string representing the network or IP address to scan,
                           e.g., "192.168.0.0/24" or "10.0.0.1".

        Raises:
            SystemExit: If the provided `ip_and_prefix` is not a valid network
                        or IP address format.
        """
        # Initialize attributes
        self.hosts_found = 0
        self.list_of_hosts_found = []
        self.filename = "hosts.txt"  # Default value for the filename

        try:
            # Use ipaddress library to parse the network string
            self.network = ipaddress.ip_network(ip_and_prefix)
        except ValueError as e:
            # Problem with input data format (e.g., malformed IP or prefix)
            sys.exit(f"Input Error: Incorrect network/prefix '{ip_and_prefix}': {e}")
        except Exception as e:
            # Catch any other unexpected errors during parsing
            sys.exit(
                f"An unexpected error occurred while parsing network/prefix '{ip_and_prefix}': {e}"
            )

        # Calculate the number of hosts
        self.network_host_count = self.network.num_addresses
        # For network masks other than /31 or /32, the network and broadcast addresses
        # are typically not considered "hosts" in traditional scans.
        if self.network.num_addresses > 2 and self.network.prefixlen not in [31, 32]:
            self.network_host_count -= 2

        # Define the ping command specific to the operating system.
        # -n 1 / -c 1: Send 1 ping request.
        # -l 1 / -s 1: Set buffer size to 1 byte.
        # -w 1000 / -w 1 / -i 1: Set timeout to 1000ms (Windows) or 1s (Linux/MacOS).
        platform_name: str = platform.system().lower()
        if platform_name == "windows":
            self.one_ping_param = "ping -n 1 -l 1 -w 1000 "
        elif platform_name == "darwin":
            self.one_ping_param = "ping -n 1 -l 1 -i 1"
        else:
            self.one_ping_param = "ping -c 1 -s 1 -w 1"

    def write_file(self, filename: Optional[str] = None) -> bool:
        """Writes the list of detected hosts to a file.

        The file can only be formatted as a simple text file for now.

        Args:
            filename: The name of the file to be written. If None or an empty
                      string, "hosts.txt" will be used as the default.

        Returns:
            bool: If the file was written successfully

        Raises:
            ValueError: If `file_type` is not 0 or 1.
        """
        # Determine the actual filename to use.
        if not filename or not filename.strip():
            self.filename = "hosts.txt"
        else:
            self.filename = filename

        data: str = ""
        for ip_addr in self.list_of_hosts_found:
            data += f"{ip_addr}\n"

        try:
            # Write data to file then return "True"
            with open(self.filename, "w") as f:
                f.write(data)
            return True
        except IOError as e:
            logger.error(
                f"File System Error: Could not write to file '{self.filename}': {e}"
            )
            return False
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while writing file '{self.filename}': {e}"
            )
            return False

    def run(self) -> None:
        """Executes the network scan by sending asynchronous pings to all hosts.

        This method orchestrates the creation of ping coroutines, groups them
        into manageable lists, runs the asyncio event loop, and processes the
        results to populate `self.nbr_host_found` and `self.list_of_hosts_found`.
        """
        # Reset scan results for a new run
        self.hosts_found = 0
        self.list_of_hosts_found = []

        # List to hold coroutine tasks for the current batch of concurrent pings.
        current_batch_tasks: List[Coroutine[Any, Any, Tuple[str, bool]]] = []
        # List of lists, where each inner list is a batch of coroutines to be run.
        all_task_batches: List[List[Coroutine[Any, Any, Tuple[str, bool]]]] = []

        # Define the maximum number of concurrent pings in a batch.
        # Limiting the number of pings simultaneously is needed to prevent
        # reaching the maximum number of shell commands allowed or to avoid
        # BlockingIOError errors on Linux systems.
        BATCH_SIZE = 128

        # Add the first empty batch list to the container.
        all_task_batches.append(current_batch_tasks)

        # Create coroutine tasks for each host in the network.
        if self.network.num_addresses == 1:
            # Special handling for /32 (single IP address network)
            # ipaddress.network.hosts() won't yield for a /32, so use network_address.
            host_ip = str(self.network.network_address)
            cmd = self.one_ping_param + host_ip
            current_batch_tasks.append(ping_coroutine(cmd, host_ip))
        else:
            # For networks with more than one address (e.g., /31, /30, /24, etc.)
            # TODO: wait...what about IPv6...
            for host in self.network.hosts():
                host_ip = str(host)
                cmd = self.one_ping_param + host_ip
                current_batch_tasks.append(ping_coroutine(cmd, host_ip))

                # If the current batch reaches BATCH_SIZE, start a new batch.
                if len(current_batch_tasks) >= BATCH_SIZE:
                    current_batch_tasks = []  # Create a new empty list for the next batch
                    all_task_batches.append(current_batch_tasks)

        # Clean up if the last added batch is empty (e.g., if total hosts was a perfect multiple of BATCH_SIZE).
        if all_task_batches and not all_task_batches[-1]:
            all_task_batches.pop()

        # If no tasks were generated (e.g., empty network range, or parsing error that didn't exit earlier)
        if not all_task_batches:
            logger.info("No hosts found to scan in the specified network range.")
            return

        # On Windows, set the ProactorEventLoopPolicy for robust subprocess handling.
        # This check prevents setting it multiple times if the program runs in an environment
        # where it might already be set or if it's not needed.
        if platform.system().lower() == "windows":
            if not isinstance(
                asyncio.get_event_loop_policy(), asyncio.WindowsProactorEventLoopPolicy
            ):
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            try:
                # Attempt to get an event loop, if none, create a ProactorEventLoop
                # This ensures an event loop is available for asyncio.run.
                asyncio.get_event_loop()
            except RuntimeError:
                asyncio.set_event_loop(asyncio.ProactorEventLoop())

        # Run all the created coroutine batches and collect the results.
        all_ping_results = asyncio.run(ping_loop(all_task_batches))

        # Process the collected results to update object attributes.
        for ip, found_status in all_ping_results:
            if found_status:
                self.hosts_found += 1
                self.list_of_hosts_found.append(ip)


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for the network scan script.

    Uses `argparse` to handle arguments such as the network to scan,
    display modes (mute, quiet), and file writing options.

    Returns:
        An argparse.Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="A network scanning tool that uses asynchronous ping operations.",
        formatter_class=argparse.RawTextHelpFormatter,  # Allows for multiline help text.
    )

    parser.add_argument(
        "network_to_scan",
        type=ipaddress.IPv4Network,
        help=(
            "The network or IP address to scan using fast pings.\n"
            'Examples: "192.168.0.0/24", "10.0.0.1", "172.16.1.128/28", etc.'
        ),
    )

    # Use a mutually exclusive group for display modes (mute, quiet, normal default).
    display_mode = parser.add_mutually_exclusive_group()
    display_mode.add_argument(
        "-m",
        "--mute",
        action="store_const",
        const=0,
        dest="mode",  # Store the value in `args.mode`
        help="Mute mode (nothing is displayed on screen during scanning).",
    )
    display_mode.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        const=1,
        dest="mode",  # Store the value in `args.mode`
        help="Quiet mode (just the list of hosts found is displayed).",
    )
    parser.set_defaults(mode=2)  # Default mode is normal (2).

    parser.add_argument(
        "-w",
        "--write-file",
        nargs="?",  # 0 or 1 argument (optional value).
        const="hosts.txt",  # Default value if -w is present but no filename given.
        metavar="FILENAME",
        help=(
            "If no filename is provided, it defaults to 'hosts.txt'.\n"
            "Example: -w local_hosts.txt or -w"
        ),
    )

    return parser.parse_args()


# Main execution block
if __name__ == "__main__":
    args = parse_arguments()

    # Determine display mode based on parsed arguments.
    # 0: mute (nothing written on screen during scanning hosts)
    # 1: quiet (just the list of hosts found is displayed)
    # 2: normal (write found hosts on screen during scanning hosts)
    mode: int = args.mode

    # Determine file saving options.
    file_to_save: bool = args.write_file is not None
    filename_to_save: Optional[str] = args.write_file

    # Create the Networkscan object.
    try:
        my_scan = Networkscan(args.network_to_scan)
    except SystemExit as e:
        logger.critical(e)  # Log critical errors before exiting.
        sys.exit(1)  # Exit with a non-zero status code to indicate error.

    # Display additional information in normal mode.
    if mode == 2:
        logger.info(f"Network to scan: {my_scan.network}")
        logger.info(f"Prefix: /{my_scan.network.prefixlen}")
        logger.info(f"Total addresses in network: {my_scan.network.num_addresses}")
        logger.info(f"Estimated number of hosts to ping: {my_scan.network_host_count}")
        logger.info("Scanning hosts...")

    # Run the scan of hosts using asynchronous pings.
    my_scan.run()

    # Display results based on the chosen mode.
    if mode != 0:  # Normal or Quiet mode
        if my_scan.list_of_hosts_found:
            if mode == 2:
                logger.info("List of hosts found:")
            # Use standard print for the actual list of hosts as it's the core output.
            for ip_addr in my_scan.list_of_hosts_found:
                print(ip_addr)
            if mode == 2:
                logger.info(f"Number of hosts found: {my_scan.hosts_found}")
        else:
            if mode == 2:
                logger.info("No hosts found.")
            elif mode == 1:
                # In quiet mode, if no hosts found, display nothing.
                pass

    # Write a file with the list of the hosts if requested.
    if file_to_save:
        if mode == 2:
            logger.info("Writing file...")
        try:
            success = my_scan.write_file(filename_to_save)
            if not success:
                logger.error(
                    f"File System Error: Failed to write file '{my_scan.filename}'"
                )
                sys.exit(1)
            elif mode == 2:
                logger.info(f"Data successfully saved into file '{my_scan.filename}'")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during file write: {e}")
            sys.exit(1)
