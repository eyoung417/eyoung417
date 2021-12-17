#!/usr/bin/env python3.6

import itertools
import json
import multiprocessing
import os
import readline
import shlex
import subprocess
import sys
import time

from terminalui import terminal

class Prompt:
    def __init__(self, prompt, file_path, number, accept_flags, flags, submenu, interactive, interpreter_path):
        self.prompt = prompt
        self.file_path = file_path
        self.number = number
        self.accept_flags = accept_flags
        self.submenu = submenu
        self.file_path = file_path
        self.flags = flags
        self.interpreter_path = interpreter_path
        self.interactive = interactive

    def __str__(self):
        return f'{self.number}. {self.prompt}'

    def run_script(self):
        if self.interactive:
            if self.interpreter_path:
                if self.flags:
                    os.execv(self.interpreter_path, [self.interpreter_path, self.file_path, self.flags])
                else:
                    os.execv(self.interpreter_path, [self.interpreter_path, self.file_path])
            else:
                if self.flags:
                    os.execv(self.file_path, [self.file_path, self.flags])
                else:
                    os.execv(self.file_path, [self.file_path])
        else:
            if self.interpreter_path:
                cmd = f'{self.interpreter_path} {self.file_path} {self.flags}'
            else:
                cmd = f'{self.file_path} {self.flags}'
            p = subprocess.Popen(shlex.split(cmd),
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 )

            for line in p.stdout.readlines():
                sys.stdout.write("\r\033[K")
                print(f'\r{line.decode().strip()}')

    def set_flags(self, flags):
        self.flags = str(flags)


def get_config():
    try:
        with open(f'{sys.path[0]}/config.json') as config:
            stored_config = json.load(config)

    except Exception as e:
        terminal.print_fail(f'Syntax error in the json of config.json\n{e}')
        sys.exit(1)

    return stored_config


def build_prompts(stored_config):
    all_prompts = []

    for index in stored_config:
        try:
            prompt = stored_config[index]['prompt']
        except KeyError as e:
            terminal.print_fail(f"Missing required parameter 'prompt' at index {index}")
            sys.exit(1)
        if 'submenu' in stored_config[index].keys():
            submenu = stored_config[index]['submenu']
        else:
            submenu = False
        if 'file_path' in stored_config[index].keys():
            if stored_config[index]['file_path'][0] == '/':
                file_path = stored_config[index]['file_path']
            else:
                file_path = os.path.abspath(os.path.dirname(__file__)) + '/' + stored_config[index]['file_path']
        else:
            file_path = None
        if 'flags' in stored_config[index].keys():
            flags = stored_config[index]['flags']
        else:
            flags = None
        if 'accept_flags' in stored_config[index].keys():
            accept_flags = stored_config[index]['accept_flags']
        else:
            accept_flags = False
        if 'interactive' in stored_config[index].keys():
            interactive = stored_config[index]['interactive']
        else:
            interactive = False
        if 'interpreter_path' in stored_config[index].keys():
            interpreter_path = stored_config[index]['interpreter_path']
        else:
            interpreter_path = '/home/nsteinbrenner/sops_toolkit/venv/bin/python3'

        all_prompts.append(Prompt(prompt=prompt,
                                  file_path=file_path,
                                  accept_flags=accept_flags,
                                  submenu=submenu,
                                  number=index,
                                  flags=flags,
                                  interactive=interactive,
                                  interpreter_path=interpreter_path,
                                  )
                           )

    return all_prompts


def check_prompts(all_prompts):
    for index, prompt in enumerate(all_prompts):
        if prompt.submenu:
            continue
        elif not os.path.isfile(prompt.file_path):
            terminal.print_fail(f'File {prompt.file_path} does not exist.')
            sys.exit(1)


def start_toolkit(all_prompts=None, nested=False):
    try:
        while True:
            terminal.print_format(terminal.return_format('\n                SOps Toolkit', 'bold'), 'yellow')
            terminal.print_format(f'         Enter {terminal.return_format("q", "red", end="cyan")} at any time to exit.', 'cyan')
            terminal.print_format(f'Enter {terminal.return_format("b", "red", end="cyan")} at any time to return to the main menu.\n', 'cyan')
            if nested is False:
                stored_config = get_config()
                all_prompts = build_prompts(stored_config)
                check_prompts(all_prompts)
            for prompt in all_prompts:
                terminal.print_info(prompt)
            choice = terminal.get_input()
            if choice == 'q':
                sys.exit(0)
            if choice == 'b' or choice == 'back':
                if nested is True:
                    return
                else:
                    continue
            if not choice:
                terminal.print_info('Please enter an option or type "q" to quit.\n', start='\n')
                continue
            try:
                int(choice)
            except ValueError:
                terminal.print_warn('Invalid input. Please try again and enter one of the numbers from the prompt.\n', start='\n')
                continue
            if int(choice) > len(all_prompts):
                terminal.print_warn('Please enter one of the numbers from the prompt.', start='\n')
                continue
            else:
                if all_prompts[int(choice)-1].accept_flags:
                    terminal.print_info('Would you like to enter any command line flags?', start='\n')
                    terminal.print_info(f'Press {terminal.return_format("enter", "red", end="blue")} without any input if not.')
                    terminal.print_info(f'Press {terminal.return_format("b", "red", end="blue")} to return to the main menu.')
                    flags = terminal.get_input()
                    if flags == 'b' or flags == 'back':
                        if nested is True:
                            return
                        else:
                            continue
                    elif flags == 'no' or flags == 'n':
                        pass
                    elif flags:
                        all_prompts[int(choice)-1].set_flags(flags)
            if all_prompts[int(choice)-1].submenu:
                all_nested_prompts = build_prompts(all_prompts[int(choice)-1].submenu)
                check_prompts(all_nested_prompts)
                nested = True
                start_toolkit(all_nested_prompts, nested)
                nested = False
                continue
            sys.stdout.write('\n')
            if not prompt.interactive:
                run_screen = (multiprocessing.Process(target=terminal.script_running_notifier))
                terminal.done = False
                run_screen.start()
            try:
                all_prompts[int(choice)-1].run_script()
            except PermissionError as e:
                if not prompt.interactive:
                    terminal.done = True
                    run_screen.terminate()
                terminal.clear_line()
                terminal.print_fail(f'Script "{all_prompts[int(choice)-1].file_path}" does not have execute permissions')
                sys.exit(1)
            except FileNotFoundError as e:
                if not prompt.interactive:
                    terminal.done = True
                    run_screen.terminate()
                terminal.clear_line()
                terminal.print_fail(f'Could not find the interpreter path "{all_prompts[int(choice)-1].interpreter_path}" when trying to run "{all_prompts[int(choice)-1].file_path}"\n{e}')
                sys.exit(1)
            except Exception as e:
                if not prompt.interactive:
                    terminal.done = True
                    run_screen.terminate()
                terminal.clear_line()
                terminal.print_fail(f'Could not run "{all_prompts[int(choice)-1].file_path}".\n{e}')
                sys.exit(1)
            except KeyboardInterrupt:
                continue
            if not prompt.interactive:
                terminal.done = True
                run_screen.terminate()
            terminal.clear_line()
            terminal.print_success('Done!', start='\n')
            while True:
                terminal.print_format(f'Do you want to run another script? ({terminal.return_format("y", "red", end="green")}/{terminal.return_format("n", "red", end="green")})', "green")
                choice = terminal.get_input()
                if choice == 'y' or choice == 'b' or choice == 'back':
                    sys.stdout.write('\n')
                    if nested is True:
                        return
                    else:
                        break
                elif choice == 'n' or choice == 'q':
                    terminal.print_info('Exiting...', start='\n')
                    sys.exit(0)
                else:
                    terminal.print_warn(f'\nPlease enter {terminal.return_format("y", "red", end="yellow")} or {terminal.return_format("n", "red", end="yellow")}.')

    except KeyboardInterrupt:
        terminal.print_info('\nExiting...', start='\n')
        sys.exit(0)


if __name__ == '__main__':
    nested = False
    start_toolkit(nested)
    sys.exit(0)
