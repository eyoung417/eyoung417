#!/usr/bin/env python3.6

import argparse
import base64
import json
import multiprocessing
import os
import readline
import requests
import secrets
import shlex
import smtplib
import string
import subprocess
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from terminalui import terminal
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Ldap:
    def __init__(self, credentials):
        self.credentials = credentials
        self.next_uid = self.get_next_uid()
        self.valid_role_ids = self.get_valid_role_ids()
        self.valid_groups = self.get_valid_groups()
        self.valid_privilege_groups = self.get_valid_privilege_groups()
        self.valid_sudo_levels = list(range(0, 7))
        self.valid_security_levels = list(range(0, 7))
        self.actions = ''

    def get_valid_groups(self):
        groups = {}
        gid = None
        group_name = None
        cmd = '/usr/bin/ldapsearch -x -LLL -u -t "(objectClass=posixGroup)"'
        for line in self.run_command(cmd):
            if 'gidNumber' in line:
                gid = line.split(' ')[1]
            elif 'cn: ' in line:
                group_name = line.split(' ')[1]
            elif line == '':
                if gid and group_name:
                    groups[group_name] = gid
                gid = None
                group_name = None
        return groups

    def get_valid_privilege_groups(self):
        privilege_groups = []
        cmd = '/usr/bin/ldapsearch -x'
        for line in self.run_command(cmd):
            if 'privilegeGroup: ' in line:
                if 'delete' in line.lower():
                    continue
                privilege_group = line.split(':')[1].strip()
                if privilege_group not in privilege_groups:
                    privilege_groups.append(privilege_group)
        return privilege_groups

    def get_valid_role_ids(self):
        role_config = f'{sys.path[0]}/roles.json'
        try:
            with open(role_config, 'r') as config:
                roles = json.load(config)
        except (FileNotFoundError, OSError) as e:
            terminal.print_fail(f'Unable to find {role_config}. Does the file exist in the scripts local directory?')
            sys.exit(1)
        except PermissionError as e:
            terminal.print_fail(f'Failed to open {role_config} due to permission settings.')
            sys.exit(1)
        except Exception as e:
            terminal.print_fail(f'Failed to read json from {role_config}')
            sys.exit(1)

        return roles

    def get_next_uid(self):
        uids = []
        cmd = '/usr/bin/ldapsearch -x'
        for line in self.run_command(cmd):
            if 'uidNumber' in line:
                uids.append(line.split(':')[1])
        return int(sorted(uids)[-1]) + 1

    def run_command(self, cmd):
        try:
            output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.PIPE).decode()
        except (FileNotFoundError, OSError) as e:
            terminal.print_fail(f'LDAP command {cmd} failed, possible syntax error. Is it spelled correctly?')
            sys.exit(1)
        return output.split('\n')

    def modify_entry(self, entry, action):
        if action == 'add':
            cmd = f'/usr/bin/ldapadd -H "ldaps://directory-master.sigfig.service" -v -x -D "{self.credentials["bind_dn"]}" -w "{self.credentials["password"]}"'
        elif action == 'modify':
            cmd = f'/usr/bin/ldapmodify -H "ldaps://directory-master.sigfig.service" -v -x -D "{self.credentials["bind_dn"]}" -w "{self.credentials["password"]}"'
        elif action == 'delete':
            cmd = f'/usr/bin/ldapdelete -H "ldaps://directory-master.sigfig.service" -v -D "{self.credentials["bind_dn"]}" -w "{self.credentials["password"]}"'

        try:
            output = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        except (FileNotFoundError, OSError) as e:
            terminal.print_fail(f'LDAP command {cmd} failed, possible syntax error. Is it spelled correctly?')
            sys.exit(1)
        
        try:
            output.communicate(input=entry.encode())
        except subprocess.TimeoutExpired as e:
            terminal.print_fail(f'Timeout expired when inputting the LDAP entry to {cmd}')
            sys.exit(1)

        self.actions += '\n' + cmd.split(' ')[0] + '\n' + entry + '\n'

    def set_current_user_values(self, ldap_entry):
        self.current_privilege_groups = []
        for line in ldap_entry:
            if 'uid: ' in line:
                self.current_uid = line.split(':')[1].strip()
            if 'gidNumber: ' in line:
                self.current_gid = line.split(':')[1].strip()
            if 'privilegeGroup: ' in line:
                self.current_privilege_groups.append(line.split(':')[1].strip())
            if 'securityLevel: ' in line:
                self.current_security_level = line.split(':')[1].strip()

    def check_valid_username(self, username, existing, quiet=False):
        cmd = f'/usr/bin/ldapsearch -x -LLL -u -t "(uid={username})"'
        found = False
        result = False
        output = self.run_command(cmd)
        for line in output:
            if f'uid: {username}' in line:
                found = True
                self.set_current_user_values(output)
        if not existing:
            if found:
                if not quiet:
                    terminal.print_warn(f'User {username} already exists. Try again.')
            else:
                result = True
        else:
            if not found:
                if not quiet:
                    terminal.print_warn(f'User {username} does not exist. Try again.')
            else:
                result = True
        return result

    def check_user_info(self, username, target_type, target=None):
        if target_type == 'sudo_level':
            cmd = f'/usr/bin/ldapsearch -xLLL -b "ou=level{target},ou=SUDOers,dc=sigfig,dc=com" "(sudoUser={username})"'
        elif target_type == 'group':
            cmd = f'/usr/bin/ldapsearch -xLLL -t -u "(&(objectClass=posixGroup)(cn={target})(memberUid={username}))"'
        elif target_type == 'privilege_group':
            cmd = f'/usr/bin/ldapsearch -xLLL -t -u "(&(objectClass=sigfigSecurityObject)(privilegeGroup={target})(uid={username}))"'
        elif target_type == 'security_level':
            cmd = f'/usr/bin/ldapsearch -xLLL -t -u "(&(securityLevel={target})(uid={username}))"'

        for line in self.run_command(cmd):
            if username in line:
                return True
        return False

    def build_entry(self, data, action_type, new_value=None):
        if action_type == 'modify':
            self.entry = (f'dn: {data.cn_override if data.cn_override else "cn=" + data.username}{"," + data.identifiers if data.identifiers else ""}\n'
                          'changetype: modify\n'
                          f'{data.action}: {data.type}\n'
                          f'{data.type}: {new_value if new_value else data.username}')
        elif action_type == 'delete':
            cmd = f'ldapsearch -xLLL -t -u "(uid={data.username})"'
            for line in self.run_command(cmd):
                if f'dn: uid={data.username}' in line:
                    self.entry = line.split(':')[1].strip() + ' '
        elif action_type == 'add':
            privilege_groups = []
            for privilege_group in self.privilege_groups:
                privilege_groups.append(f'privilegeGroup: {privilege_group}\n')
            self.entry = (f'dn: uid={data.username},ou=People,dc=sigfig,dc=com\n'
                          f'cn: {data.first_name} {data.last_name}\n'
                          f'mail: {data.email}\n'
                          f'givenName: {data.first_name}\n'
                          f'gidNumber: {data.gid}\n'
                          f'homeDirectory: /home/{data.username}\n'
                          f'sn: {data.last_name}\n'
                          'loginshell: /bin/bash\n'
                          'objectClass: inetOrgPerson\n'
                          'objectClass: posixAccount\n'
                          'objectClass: sigfigSecurityObject\n'
                          'objectClass: top\n'
                          f'{"".join(privilege_groups)}'
                          f'uidNumber: {self.next_uid}\n'
                          f'uid: {data.username}\n'
                          f'securityLevel: {data.security_level}')


class LdapData(Ldap):
    def __init__(self, credentials):
        Ldap.__init__(self, credentials)
        self.identifiers = 'ou=People,dc=sigfig,dc=com'
        self.type = None
        self.new_value = None
        self.cn_override = None

    def set_username(self, existing=False):
        while True:
            username = terminal.get_input(message='Username', message_option='blue')
            result = self.check_valid_username(username, existing)
            if result:
                self.username = username
                break
            else:
                continue

    def set_batch_usernames(self):
        self.batch_usernames = []
        while True:
            batch_file = terminal.get_input(message='Enter path to file', message_option='blue')
            if not os.path.isfile(batch_file):
                terminal.print_warn(f'{batch_file} is not a valid file. Try again')
                continue
            else:
                break
        with open(batch_file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            result = self.check_valid_username(line.strip(), existing=True, quiet=True)
            if result:
                self.batch_usernames.append(line.strip())
            else:
                terminal.print_warn(f'User {line.strip()} does not exist. Skipping...')

    def set_group(self, existing=False):
        while True:
            terminal.print_info(f'Which group should the user {"belong to" if not existing else "be added to or removed from"}?')
            for index, group_name in enumerate(self.valid_groups.keys()):
                terminal.print_info(str(index+1) + '. ' + terminal.return_format(group_name, "red", end="blue"))
            group = terminal.get_input(message='Enter a group', message_option='blue')

            if group.isdigit():
                if int(group) - 1 < len(list(self.valid_groups.keys())) and int(group) - 1 >= 0:
                    group = list(self.valid_groups.keys())[int(group)-1]
                else:
                    terminal.print_warn(f'{group} was outside of the range of numbers. Please try again')
                    continue

            if group not in self.valid_groups.keys():
                terminal.print_warn(f'{group} is not a valid group. Groups are case sensitive.')
                continue
            else:
                self.group = group
                self.gid = self.valid_groups[self.group]
                break

    def set_user_info(self):
        self.first_name = terminal.get_input(message=f'First Name', message_option='blue').title()
        self.last_name = terminal.get_input(message=f'Last Name', message_option='blue').title()
        self.email = terminal.get_input(message=f'E-mail', message_option='blue')

    def set_privilege_group(self, existing=False):
        while True:
            privilege_groups = []
            error = False
            terminal.print_info(f'Which privilege group(s) should the user {"belong to" if not existing else "be added or removed from"}?')
            for index, group in enumerate(self.valid_privilege_groups):
                terminal.print_info(str(index+1) + '. ' + terminal.return_format(group, "red"))
            terminal.print_info(f'If entering more than one privilege group, please separate them with spaces or with commas.\nExample 1: {terminal.return_format("SigFig SigFigDev", "red", end="blue")}\nExample 2: {terminal.return_format("SigFig,SigFigDev", "red", end="blue")}')
            privilege_group = terminal.get_input(message='Enter case-sensitive privilege group(s)', message_option='blue')
            if ',' in privilege_group:
                privilege_group = privilege_group.split(',')
                for group in privilege_group:
                    if ',' in group:
                        group = group.replace(',', '')
                    if group not in privilege_groups:
                        privilege_groups.append(group.strip())
            elif ' ' in privilege_group:
                privilege_group = privilege_group.split(' ')
                for group in privilege_group:
                    if group not in privilege_groups:
                        privilege_groups.append(group.strip())
            else:
                privilege_groups.append(privilege_group.strip())
            privilege_groups = list(filter(None, privilege_groups))
            for index, group in enumerate(privilege_groups):
                if group.isdigit():
                    if int(group) - 1 < len(self.valid_privilege_groups) and int(group) - 1 >= 0:
                        privilege_groups[index] = self.valid_privilege_groups[int(group)-1]
                        group = self.valid_privilege_groups[int(group)-1]
                    else:
                        terminal.print_warn(f'{group} was outside of the range of numbers. Please try again')
                        error = True
                        break
                if group not in self.valid_privilege_groups:
                    terminal.print_warn(f'Privilege group {group} does not exist. Groups are case sensitive')
                    error = True
                    break
            if error:
                continue
            break
        self.privilege_groups = privilege_groups

    def set_security_level(self, existing=False):
        while True:
            security_level = terminal.get_input(message=f'Security level ({terminal.return_format(str(self.valid_security_levels[0]) + "-" + str(self.valid_security_levels[-1]), "red", end="blue")})', message_option='blue')
            if int(security_level) not in self.valid_security_levels:
                terminal.print_warn(f'Security level {security_level} is not valid.')
                continue
            elif existing:
                if self.current_security_level == security_level:
                    terminal.print_warn(f'User {self.username} is already in security level {security_level}')
                    continue
            break
        self.security_level = security_level

    def set_sudo_level(self, single=True):
        sudo_levels = []
        while True:
            if not single:
                terminal.print_info(f'EXAMPLE: If you specify {terminal.return_format(self.valid_sudo_levels[-1], "red", end="blue")}, sudo levels {terminal.return_format(self.valid_sudo_levels[0], "red", end="blue")}-{terminal.return_format(self.valid_sudo_levels[-1], "red", end="blue")} would be added or removed.')
            sudo_level = terminal.get_input(message=f'Sudo level(s) ({terminal.return_format(self.valid_sudo_levels[0], "red", end="blue")}-{terminal.return_format(self.valid_sudo_levels[-1], "red", end="blue")})', message_option='blue')
            if single:
                if int(sudo_level) not in self.valid_sudo_levels:
                    terminal.print_warn(f'Sudo access level {sudo_level} is not valid.')
                    continue
                else:
                    sudo_levels.append(sudo_level)
                    break
            else:
                if int(sudo_level) not in self.valid_sudo_levels:
                    terminal.print_warn(f'{sudo_level} is outside of the range ({self.valid_sudo_levels[0]}-{self.valid_sudo_levels[-1]}).')
                    continue
                if not sudo_level.isdigit():
                    terminal.print_warn('Please enter a number only.')
                    continue
                for sudo_level in self.valid_sudo_levels[:self.valid_sudo_levels.index(int(sudo_level))+1]: 
                    sudo_levels.append(str(sudo_level))
                break
        self.sudo_levels = sudo_levels

    def set_command(self):
        self.command = terminal.get_input(message=f'Enter the command (e.g {terminal.return_format("/opt/antonium/bin/antonium", "red", end="blue")})', message_option='blue')

    def set_action(self, message=None):
        if message == None:
            message = f'Do you want to add or remove user {terminal.return_format(self.username, "yellow", end="blue")}?'
        while True:
            action = terminal.get_input(message=message + f' ({terminal.return_format("add", "red", end="blue")}/{terminal.return_format("del", "red", end="blue")})', message_option='blue')
            if action.strip().lower() == 'add':
                self.action = 'add'
                break
            elif action.strip().lower() == 'del' or action.strip().lower() == 'delete':
                self.action = 'delete'
                break
            else:
                terminal.print_warn('Please specify "add" or "del".')
                continue

    def set_role(self):
        while True:
            terminal.print_info('Please select a valid role ID from the list below.')
            for index, role_id in enumerate(self.valid_role_ids):
                terminal.print_info(str(index+1) + '. ' + terminal.return_format(role_id, "red"))
            role_id = terminal.get_input(message='Enter role ID', message_option='blue')
            if role_id.isdigit():
                if int(role_id) - 1 < len(self.valid_role_ids.keys()) and int(role_id) - 1 >= 0:
                    role_id = list(self.valid_role_ids.keys())[int(role_id)-1]
                else:
                    terminal.print_warn(f'{role_id} was outside of the range of numbers. Please try again')
                    continue
            if role_id not in self.valid_role_ids.keys():
                terminal.print_warn('Please enter a valid role ID from the list.')
                continue
            else:
                while True:
                    verify = terminal.get_input(message=f'Is {terminal.return_format(role_id, "yellow", end="blue")} the correct role ID? ({terminal.return_format("y", "red", end="blue")}/{terminal.return_format("n", "red", end="blue")})', message_option='blue')
                    if verify.strip().lower() == 'y' or verify.strip().lower() == 'yes' or verify.strip().lower() == 'n' or verify.strip().lower() == 'no':
                        break
                    else:
                        terminal.print_warn('Please specify either "y" or "n"')
                        continue
            if verify.strip().lower() == 'y' or 'yes':
                break
            else:
                continue

        self.role_id = role_id
        self.security_level = self.valid_role_ids[self.role_id]['security_level']
        self.gid = self.valid_role_ids[self.role_id]['group']
        for group_key, gid in self.valid_groups.items():
            if gid == self.gid:
                self.group = group_key
        self.privilege_groups = self.valid_role_ids[self.role_id]['privilege_group']
        self.sudo_levels = self.valid_role_ids[self.role_id]['sudo_level']

    def check_selection(self, selection, selection_type):
        flag = False
        all_checks = []
        if not isinstance(selection, list):
            selection = selection.split(' ')
        dedup_selection = selection[:]
        for item in selection:
            all_checks.append(self.check_user_info(self.username, selection_type, target=item))
        for result, target in zip(all_checks, selection):
            if self.action == 'add':
                if result:
                    flag = True
            elif self.action == 'delete':
                if not result:
                    flag = True
            if flag:
                flag = False
                dedup_selection.remove(target)
                terminal.print_warn(f'{self.username} is {"already in" if self.action == "add" else "not in"} {selection_type} {target}. Skipping...')
        if len(dedup_selection) < 1:
            terminal.print_warn(f'{self.username} is {"already in all" if self.action == "add" else "not in all"} specified {selection_type}s: {",".join(selection)}. Please try again.')
            return False
        else:
            return dedup_selection


class Kerberos:
    def __init__(self, username):
        self.username = username
        self.valid_principals = ['', '/secure', '/admin']

    def generate_password(self):
        all_characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(all_characters) for i in range(32))

    def get_principals(self, security_level):
        if int(security_level) == 6:
            principals = ['', '/secure', '/admin']
        elif int(security_level) >= 3 and int(security_level) < 6:
            principals = ['', '/secure']
        else:
            principals = ['']
        return principals

    def run_command(self, cmd, entry):
        try:
            kadmin = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        except (FileNotFoundError, OSError) as e:
            terminal.print_fail(f'kadmin command {cmd} failed, possible syntax error. Is it spelled correctly?\n{e}')
            sys.exit(1)

        try:
            kadmin.communicate(entry.encode())
        except subprocess.TimeoutExpired as e:
            terminal.print_fail(f'Timeout expired when inputting the kadmin entry to {cmd}\n{e}')
            sys.exit(1)

    def modify_principal(self, principal, action, quiet=False):
        cmd = '/usr/sbin/kadmin.local'
        logins = {}
        if action == 'add':
            password = self.generate_password()
            modify_princ = f'add_principal {self.username}{principal}\n{password}\n{password}\n'
            logins['username'] = self.username + principal
            logins['password'] = password
            terminal.print_info(f'New principal {terminal.return_format(self.username + principal, "yellow", end="blue")}: ' + terminal.return_format(password, "yellow", end="blue"))
        elif action == 'delete':
            modify_princ = f'delete_principal {self.username}{principal}\nyes\n'
            if not quiet:
                terminal.print_info(f'Deleted principal: {terminal.return_format(self.username + principal, "yellow", end="blue")}')
        self.run_command(cmd, modify_princ)
        return logins 


class Jira:
    def __init__(self, credentials):
        self.username = credentials['username']
        self.password = credentials['password']
        self.token = base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()
        self.headers = {'Content-Type': 'application/json',
                        'Authorization': f'Basic {self.token}',
                        'maxResults': '-1',
                        }

    def set_ticket_number(self):
        while True:
            not_correct = None
            ticket_number = terminal.get_input(message=f'Which JIRA ticket is this request associated with? (Example: {terminal.return_format("INFRA-1234", "red", end="blue")})', message_option='blue')
            ticket = self.get_ticket_info(ticket_number)
            if not ticket:
                continue
            if len(ticket['issues']) > 1:
                raise ValueError(f'More than 1 ticket returned for {ticket_number}')
            try:
                terminal.print_info(f'Issue description: {ticket["issues"][0]["fields"]["summary"]}')
            except IndexError as e:
                terminal.print_fail(f'{ticket_number} does not exist.')
                continue
            while True:
                confirm = terminal.get_input(message=f'Is this the right issue? ({terminal.return_format("y", "red", end="blue")}/{terminal.return_format("n", "red", end="blue")})', message_option='blue')
                if confirm.strip().lower() == 'y' or confirm.strip().lower() == 'yes':
                    self.ticket_number = ticket_number
                    break
                elif confirm.strip().lower() == 'n' or confirm.strip().lower() == 'no':
                    not_correct = True
                    break
                else:
                    terminal.print_warn(f'{confirm} is not a valid response. Please enter "y" or "n".')
                    continue
            if not_correct == True:
                continue
            break

    def get_ticket_info(self, ticket_number):
        jira_url = f'https://jira-v01-1.corp-us-west.sigfig.host/rest/api/latest/search?jql=key%20%3D%20{ticket_number}'
        try:
            jira_request = requests.get(jira_url, headers=self.headers, verify=False)
            jira_request.raise_for_status()
        except Exception as e:
            terminal.print_warn(f'Failed to access {jira_url}. Check for a typo in the ticket number, malformed URL, or connection problems. HTTP Status code: {jira_request.status_code}\nPlease try again.')
            return False

        return jira_request.json()

    def add_ticket_comment(self, actions):
        comment = {'body': f'LDAP Changes applied using script:\n\n{"".join(actions)}'}
        jira_url = f'https://jira-v01-1.corp-us-west.sigfig.host/rest/api/latest/issue/{self.ticket_number}/comment'
        try:
            add_comment = requests.post(jira_url, data=json.dumps(comment), headers=self.headers, verify=False)
            add_comment.raise_for_status()
        except requests.exceptions.HTTPError as e:
            terminal.print_fail(f'Failed to access {jira_url}. Check for a typo in the ticket number, malformed URL, or connection problems. HTTP Status code: {add_comment.status_code}\n{e}')
            sys.exit(1)


def get_credentials(password_file, credential_type):
    if credential_type == 'ldap':
        try:
            with open(password_file, 'r') as f:
                for line in f.readlines():
                    if 'bind dn' in line.lower():
                        bind_dn = line.split(':')[1].strip()
                    elif 'password' in line.lower():
                        password = line.split(':')[1].strip()
                    elif 'kerberos master key' in line.lower():
                        kerberos_key = line.split(':')[1].strip()
        except (FileNotFoundError, OSError) as e:
            terminal.print_fail(f'Failed to retrieve data from {password_file} Check that file exists, and the above spelling is correct.')
            sys.exit(1)
        return {'bind_dn': bind_dn, 'password': password, 'kerberos_key': kerberos_key}

    elif credential_type == 'jira':
        try:
            with open(password_file, 'r') as f:
                for line in f.readlines():
                    if 'username' in line.lower():
                        username = line.split(':')[1].strip()
                    elif 'password' in line.lower():
                        password = line.split(':')[1].strip()
        except (FileNotFoundError, OSError) as e:
            terminal.print_fail(f'Failed to retrieve data from {password_file} Check that file exists, and the above spelling is correct.')
            sys.exit(1)
        return {'username': username, 'password': password}

def email_user(ldap, logins):
    if ldap.email.split('@')[1] != 'sigfig.com':
        terminal.print_warn(f'Cannot send e-mail to {ldap.email} because the domain is not "sigfig.com". Please send the e-mail manually.')
        return
    terminal.print_info(f'Sending e-mail to {terminal.return_format(ldap.email, "yellow", end="blue")}...')
    formatted_logins = []
    secure = False
    admin = False
    for login in logins:
        if '/secure' in login['username']:
            secure = True
        elif '/admin' in login['username']:
            admin = True
        login['password'] = login['password'].replace('<', '&lt;')
        login['password'] = login['password'].replace('>', '&gt;')
        formatted_logins.append('<b>' + login['username'] + '</b>' + ': ' + login['password'])
    fromaddr = 'team-sops@sigfig.com'
    toaddr = ldap.email
    ccaddr = ''
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['CC'] = ccaddr
    msg['Subject'] = 'New LDAP Credentials'
    body = f'''\
<html>
  <head></head>
  <body>
    Hello <b>{ldap.first_name} {ldap.last_name}</b>,<br/><br/>
    I've given you a temporary password, though you can change it as soon as you're logged in.<br/><br/>
    Your login(s):<br/><br/>{'<br/>'.join(formatted_logins)}<br/><br/>
    These are LDAP credentials to allow you to SSH into various hosts depending on your security level. Your security level is <b>{ldap.security_level}</b>.<br/><br/>
    {'<b>' + ldap.username + '</b>'} is for hosts with a security level less than <b>3</b>.<br/>
    {'<b>' + ldap.username + '/secure</b> is for hosts with a security level greater than or equal to <b>3</b> and less than <b>5</b>.<br/>' if secure else ''}
    {'<b>' + ldap.username + '/admin</b> is for hosts with a security level above <b>5</b>.<br/>' if admin else ''}<br/>
    The security level of the host is determined by the SSH banner, if there is no SSH banner the security level is less than <b>3</b>.<br/><br/>
    To reset your password, log into any host for which you have valid credentials and use the <b>kpasswd</b> command specifying each of your usernames. It will prompt you once for your old password, then twice for your new one.  Then it'll either update your password or tell you which complexity requirements you failed and ask you to try again.<br/><br/>
    Best regards,<br/>
    Site Operations<br/>
    team-sops@sigfig.com
    </body>
</html>
            '''
    msg.attach(MIMEText(body, 'html'))
    server = smtplib.SMTP('localhost', 25)
    server.ehlo()
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr, text)

def modify_sudo_levels(ldap, target_sudo_level=None):
    sudo_levels = []
    if not target_sudo_level and target_sudo_level not in ldap.valid_sudo_levels:
        ldap.set_username(existing=True)
        while True:
            if args.sudorange:
                ldap.set_sudo_level(single=False)
            else:
                ldap.set_sudo_level()
            ldap.set_action()
            result = ldap.check_selection(ldap.sudo_levels, 'sudo_level')
            if not result:
                continue
            else:
                ldap.sudo_levels = result
                break
        sudo_levels = ldap.sudo_levels
    else:
        sudo_levels.append(target_sudo_level)
    ldap.type = 'sudoUser'
    ldap.cn_override = 'cn=defaults'
    if len(sudo_levels) > 0:
        for sudo_level in sudo_levels:
            ldap.identifiers = f'ou=level{sudo_level},ou=SUDOers,dc=sigfig,dc=com'
            ldap.build_entry(ldap, 'modify')
            ldap.modify_entry(ldap.entry, 'modify')

def modify_group(ldap, target_group=None):
    if not target_group:
        ldap.set_username(existing=True)
        while True:
            ldap.set_group(existing=True)
            ldap.set_action()
            result = ldap.check_selection(ldap.group, 'group')
            if not result:
                continue
            else:
                ldap.group = ''.join(result)
                break
        group = ldap.group
    else:
        group = target_group
    ldap.cn_override = 'cn=' + group
    ldap.type = 'memberUid'
    ldap.identifiers = 'ou=Group,dc=sigfig,dc=com'
    ldap.build_entry(ldap, 'modify')
    ldap.modify_entry(ldap.entry, 'modify')

def modify_privilege_group(ldap, target_privilege_groups=None):
    if not target_privilege_groups:
        ldap.set_username(existing=True)
        while True:
            ldap.set_privilege_group(existing=True)
            ldap.set_action()
            result = ldap.check_selection(ldap.privilege_groups, 'privilege_group')
            if not result:
                continue
            else:
                ldap.privilege_groups = result
                break
        privilege_groups = ldap.privilege_groups
    else:
        privilege_groups = target_privilege_groups
    ldap.type = 'privilegeGroup'
    ldap.cn_override = 'uid=' + ldap.username
    for privilege_group in privilege_groups:
        ldap.build_entry(ldap, 'modify', new_value=privilege_group)
        ldap.modify_entry(ldap.entry, 'modify')

def modify_security_level(ldap, target_security_level=None, manage_kerberos=True):
    logins = []
    if not target_security_level:
        ldap.set_username(existing=True)
        ldap.set_security_level(existing=True)
        security_level = ldap.security_level
    else:
        security_level = target_security_level
    ldap.action = 'replace'
    ldap.cn_override = 'uid=' + ldap.username
    ldap.type = 'SecurityLevel'
    ldap.build_entry(ldap, 'modify', new_value=security_level)
    ldap.modify_entry(ldap.entry, 'modify')
    if manage_kerberos:
        kadmin = Kerberos(ldap.username)
        old_principals = kadmin.get_principals(ldap.current_security_level)
        new_principals = kadmin.get_principals(ldap.security_level)
        for principal in old_principals:
            if principal not in new_principals:
                kadmin.modify_principal(principal, 'delete')
        for principal in new_principals:
            if principal not in old_principals:
                logins.append(kadmin.modify_principal(principal, 'add'))

def modify_sudo_command(ldap, target_sudo_command=None):
    if not target_sudo_command:
        ldap.set_username(existing=False)
        ldap.set_command()
        message = f'Do you want to add or remove sudoCommand {terminal.return_format(ldap.command, "yellow", end="blue")} for user {terminal.return_format(ldap.username, "yellow", end="blue")}?'
        ldap.set_action(message=message)
        command = ldap.command
    else:
        command = target_sudo_command
    ldap.type = 'sudoCommand'
    ldap.identifiers = f'ou=base,ou=SUDOers,dc=sigfig,dc=com'
    ldap.build_entry(ldap, 'modify', new_value=command)
    ldap.modify_entry(ldap.entry, 'modify')

def add_user_manually(ldap):
    logins = []
    ldap.set_username()
    ldap.set_user_info()
    ldap.set_group()
    ldap.set_privilege_group()
    ldap.set_security_level()
    ldap.set_sudo_level(single=False)
    ldap.build_entry(ldap, 'add')
    ldap.modify_entry(ldap.entry, 'add')
    ldap.action = 'add'
    modify_group(ldap, target_group=ldap.group)
    if ldap.sudo_levels is not None:
        for sudo_level in ldap.sudo_levels:
            modify_sudo_levels(ldap, target_sudo_level=sudo_level)
    kadmin = Kerberos(ldap.username)
    new_principals = kadmin.get_principals(ldap.security_level)
    for principal in new_principals:
        logins.append(kadmin.modify_principal(principal, 'add'))
    #email_user(ldap, logins)

def add_user_by_role_id(ldap):
    logins = []
    ldap.set_username()
    ldap.set_user_info()
    ldap.set_role()
    ldap.build_entry(ldap, 'add')
    ldap.modify_entry(ldap.entry, 'add')
    ldap.action = 'add'
    modify_group(ldap, target_group=ldap.group)
    if ldap.sudo_levels is not None:
        for sudo_level in ldap.sudo_levels:
            modify_sudo_levels(ldap, target_sudo_level=sudo_level)
    kadmin = Kerberos(ldap.username)
    new_principals = kadmin.get_principals(ldap.security_level)
    for principal in new_principals:
        logins.append(kadmin.modify_principal(principal, 'add'))
    #email_user(ldap, logins)

def decommission_user(ldap):
    usernames = []
    if args.deleteuser or args.deletebatch:
        terminal.print_warn(f'This option {terminal.return_format("DELETES", "red", end="yellow")} a user. For termination requests, please use the "Deactivate" counterpart (option 8 or 9).')
    if args.deactivatebatch or args.deletebatch:
        ldap.set_batch_usernames()
        for username in ldap.batch_usernames:
            usernames.append(username)
    else:
        ldap.set_username(existing=True)
        usernames.append(ldap.username)
    for username in usernames:
        ldap.username = username
        ldap.action = 'replace'
        modify_privilege_group(ldap, target_privilege_groups=['Deleted'])
        modify_security_level(ldap, target_security_level='0', manage_kerberos=False)
        ldap.action = 'delete'
        for sudo_level in ldap.valid_sudo_levels:
            if ldap.check_user_info(ldap.username, 'sudo_level', sudo_level):
                modify_sudo_levels(ldap, target_sudo_level=sudo_level)
        for group in ldap.valid_groups:
            if ldap.check_user_info(ldap.username, 'group', group):
                modify_group(ldap, target_group=group)
        if args.deleteuser or args.deletebatch:
            ldap.build_entry(ldap, 'delete')
            ldap.modify_entry(ldap.entry, 'delete')
        kadmin = Kerberos(ldap.username)
        terminal.print_info(f'Deleting all principals for {terminal.return_format(ldap.username, "yellow", end="blue")}...')
        for principal in kadmin.valid_principals:
            kadmin.modify_principal(principal, 'delete', quiet=True)

def main():
    if args.add:
        add_user_manually(ldap)
    if args.role:
        add_user_by_role_id(ldap)
    if args.group:
        modify_group(ldap)
    if args.privilegegroup:
        modify_privilege_group(ldap)
    if args.sudo or args.sudorange:
        modify_sudo_levels(ldap)
    if args.security:
        modify_security_level(ldap)
    if args.sudocommand:
        modify_sudo_command(ldap)
    if args.deactivateuser or args.deactivatebatch or args.deleteuser or args.deletebatch:
        decommission_user(ldap)
    terminal.print_info(f'Adding comment to {terminal.return_format(jira.ticket_number, "yellow", end="blue")}...')
    jira.add_ticket_comment(ldap.actions)
    terminal.print_success('Done!')
    terminal.print_info('Exiting...', start='\n')


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    terminal.done = False
    run_screen = (multiprocessing.Process(target=terminal.script_running_notifier))
    run_screen.start()
    ldap_password_file = '/home/nsteinbrenner/ldap_kerberos'
    jira_password_file = '/home/nsteinbrenner/automation_user_jira.yml'
    ldap_credentials = get_credentials(ldap_password_file, 'ldap')
    jira_credentials = get_credentials(jira_password_file, 'jira')

    jira = Jira(jira_credentials)
    ldap = LdapData(ldap_credentials)
    terminal.done = True
    run_screen.terminate()
    sys.stdout.write('\r\033[K')

    jira.set_ticket_number()

    parser = argparse.ArgumentParser(prog='SOPs LDAP Access Request Script', description='Performs access request LDAP functions.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--add', default=False, action='store_true', required=False, help='Add LDAP user')
    group.add_argument('--deactivatebatch', default=False, action='store_true', required=False, help='Deactivate users from a batch file.')
    group.add_argument('--deactivateuser', default=False, action='store_true', required=False, help='Deactivate LDAP user.')
    group.add_argument('--group', default=False, action='store_true', required=False, help='Modify LDAP user group')
    group.add_argument('--deleteuser', default=False, action='store_true', required=False, help='Delete LDAP user')
    group.add_argument('--sudocommand', default=False, action='store_true', required=False, help='Add user sudo command')
    group.add_argument('--sudorange', default=False, action='store_true', required=False, help='Modify sudo group level by range or list')
    group.add_argument('--privilegegroup', default=False, action='store_true', required=False, help='Modify LDAP user privilege group')
    group.add_argument('--role', default=False, action='store_true', required=False, help='Add new user based off role ID')
    group.add_argument('--security', default=False, action='store_true', required=False, help='Modify security level.')
    group.add_argument('--deletebatch', default=False, action='store_true', required=False, help='Delete LDAP users from batch file.')
    group.add_argument('--sudo', default=False, action='store_true', required=False, help='Modify sudo group level.')
    args = parser.parse_args()

    main()
