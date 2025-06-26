#!/usr/bin/env python3
import os
import shlex
import subprocess
import readline

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT     = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
INTERCEPTOR_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "interceptor.so"))

# The working directory for the shell session
current_dir = PROJECT_ROOT

def print_banner():
    print("\n🛡️  Welcome to CipherWing Shell — Real-time Malware Defense Terminal")
    print("Type commands like in a normal shell. 'cd', 'ls', 'pwd' all work.")
    print("All file access is scanned live.\nType 'exit' to quit.\n")

def error(msg): print(f"[!] {msg}")

def run_command(user_input: str):
    global current_dir

    if user_input.strip() == "":
        return

    # Built-ins
    if user_input in {"exit", "quit"}:
        print("👋 Exiting CipherWing Shell."); raise SystemExit
    if user_input == "clear":
        os.system("clear"); return
    if user_input == "help":
        print("Built-ins: cd, ls, pwd, clear, exit, help"); return

    # Handle `cd` command
    if user_input.startswith("cd"):
        parts = user_input.strip().split()
        target = parts[1] if len(parts) > 1 else os.path.expanduser("~")
        new_path = os.path.abspath(os.path.join(current_dir, target))
        if os.path.isdir(new_path):
            current_dir = new_path
        else:
            error(f"No such directory: {new_path}")
        return

    # `pwd` command
    if user_input.strip() == "pwd":
        print(current_dir); return

    # `ls` command
    if user_input.strip() == "ls":
        try:
            for f in os.listdir(current_dir):
                print(f)
        except Exception as e:
            error(f"ls failed: {e}")
        return

    # All other commands (cat, nano, etc.)
    if not os.path.exists(INTERCEPTOR_PATH):
        error(f"interceptor.so not found at {INTERCEPTOR_PATH}")
        return

    try:
        command_parts = shlex.split(user_input)
    except ValueError as ve:
        error(f"Parse error: {ve}")
        return

    env = os.environ.copy()
    env["LD_PRELOAD"] = INTERCEPTOR_PATH

    try:
        subprocess.run(command_parts, env=env, cwd=current_dir)
    except FileNotFoundError:
        error(f"Command not found: {command_parts[0]}")
    except Exception as e:
        error(f"Error running command: {e}")

def main():
    print_banner()
    while True:
        try:
            prompt = f"💀 cipherwing ({os.path.basename(current_dir)})> "
            user_input = input(prompt)
            run_command(user_input)
        except KeyboardInterrupt:
            print("\n[CTRL+C] Use 'exit' to quit.")
        except EOFError:
            print("\n[CTRL+D] Goodbye."); break

if __name__ == "__main__":
    main()
