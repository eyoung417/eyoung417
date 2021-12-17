#!/usr/bin/env python3.6

import sys
import time
import itertools


class TerminalUI:
    def __init__(self):
        self.done = False
        # prompts
        self.initial = '➜ '
        self.succeed = '✓ '
        self.warning = '! '
        self.fail = '✘ '
        self.info = '» '
        # colors
        self.purple = '\033[95m'
        self.cyan = '\033[96m'
        self.dark_cyan = '\033[36m'
        self.blue = '\033[94m'
        self.green = '\033[92m'
        self.yellow = '\033[93m'
        self.red = '\033[91m'
        self.bold = '\033[1m'
        self.underline = '\033[4m'
        self.endc = '\033[0m'
        self.back_black = '\033[40m'
        self.back_red = '\033[41m'
        self.back_green = '\033[42m'
        self.back_yellow = '\033[43m'
        self.back_blue = '\033[44m'
        self.back_magenta = '\033[45m'
        self.back_cyan = '\033[46m'
        self.back_white = '\033[47m'

        self.options_dict = {'purple': self.purple,
                             'cyan': self.cyan,
                             'dark_cyan': self.dark_cyan,
                             'blue': self.blue,
                             'green': self.green,
                             'yellow': self.yellow,
                             'red': self.red,
                             'magenta': self.back_magenta,
                             'black': self.back_black,
                             'white': self.back_white,
                             'bold': self.bold,
                             'underline': self.underline,
                             }

    def get_input(self, message=None, message_option=None):
        if message_option:
            if message_option in self.options_dict.keys():
                message_option = self.options_dict[message_option]
            else:
                self.print_fail(f'Could not find message options {message_option}')
                sys.exit(1)
            if not message:
                self.print_fail('A message is required for the message_option parameter')
                sys.exit(1)
            user_input = input(message_option +  message + self.endc + ' ' + self.bold + self.initial + self.endc).strip()
        else:
            if message:
                user_input = input(message + ' ' + self.bold + self.initial + self.endc).strip()
            else:
                user_input = input(self.bold + self.initial + self.endc).strip()
        if user_input == 'q' or user_input == 'quit':
            self.print_info('Exiting...', start='\n')
            sys.exit(1)
        return user_input

    def script_running_notifier(self):
        chars = [self.cyan + char + self.endc for char in ['\r\033[K•', '\r\033[K••', '\r\033[K•••', '\r\033[K••••']]
        for character in itertools.cycle(chars):
            try:
                if self.done:
                    break
                sys.stdout.write(f'\r{character}')
                time.sleep(.50)
                sys.stdout.flush()
            except KeyboardInterrupt:
                break

    def clear_line(self):
        sys.stdout.write('\r\033[K')

    def print_success(self, message, start='', end='\n'):
        print(start + self.green + self.succeed + str(message) + self.endc, end=end)

    def print_warn(self, message, start='', end='\n'):
        print(start + self.yellow + self.warning + str(message) + self.endc, end=end)

    def print_fail(self, message, start='', end='\n'):
        print(start + self.red + self.fail + str(message) + self.endc, end=end)

    def print_info(self, message, start='', end='\n'):
        print(start + self.blue + self.info + str(message) + self.endc, end=end)

    def print_format(self, message, option):
        if option in self.options_dict.keys():
            print(self.options_dict[option] + str(message) + self.endc)
        else:
            self.print_fail(f'Could not find color {option}')
            sys.exit(1)

    def return_format(self, message, option, end=True):
        if end is True:
            end = self.endc
        elif end in self.options_dict.keys():
            end = self.options_dict[end]
        if option in self.options_dict.keys():
            return(self.options_dict[option] + str(message) + end)
        else:
            self.print_fail(f'Could not find color {option}')
            sys.exit(1)

terminal = TerminalUI()
