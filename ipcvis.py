#! /usr/bin/env python
"""
ipcvis - visualize inter-process communication.

Small script that is able to create graph of verious IPC communication channels
between processes, together with their process hierarchy
"""

# --------------------------------------------------------------------------------
# ipcvis- visualize inter-process communication
# Copyright (C) 2015 Tamas Palagyi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# --------------------------------------------------------------------------------

import os
import sys
import subprocess
import argparse
import logging

import pygraphviz as gv

from collections import namedtuple

# --------------------------------------------------------------------------------

logging.basicConfig()
LOG = logging.getLogger('ipcvis')
# LOG.setLevel(logging.DEBUG)

# --------------------------------------------------------------------------------

ProcessRecord = namedtuple('ProcessRecord', 'process_name pid ppid command')

# --------------------------------------------------------------------------------

PROCESS_PID = 'p'
PROCESS_LOGIN_NAME = 'L'
PROCESS_USER_ID = 'u'
PROCESS_NAME = 'c'

PROTOCOL_NAME = 'P'
FILE_TYPE = 't'
FILE_DESCRIPTOR = 'f'
INODE_NUMBER = 'i'
FILE_NAME = 'n'

SHMEM_FILENAME = '/SYSV'

# -------------------------------------------------------------------------------
# Utilities
# -------------------------------------------------------------------------------


def check_root():
    """Check if user running this script is root."""
    if os.geteuid() != 0:
        msg = """You do not have root privileges.
Without root privileges this program is not able to retrieve all needed system details.
Exiting..."""

        exit(msg)


def get_stdout(cmd):
    """Return stdout of cmd."""
    fnull = open(os.devnull, 'w')
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=fnull).stdout
    return pipe.read()


def cmdparser():
    """Responsible for parsing command line argument."""
    parser = argparse.ArgumentParser(description='This program records inter-process communication details and visualize them.')
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('-v', '--version', help='show version information', action='store_true')
    parser.add_argument('-n', '--noroot', help='does not check for root privileges', action='store_true')
    group.add_argument('-r', "--record", help='record', action='store_true')
    group.add_argument('-l', "--load", help='load', action='store_true')
    parser.add_argument('-t', '--title', help='diagram title (default: %(default)s)', default='IPC visualization')
    parser.add_argument('-f', '--file', help='record file (default: %(default)s)', default='ipcvis.ipcdump')
    parser.add_argument('-o', '--out', help='output file for rendering (default: %(default)s)', default='ipcvis.png')

    return parser.parse_args()


def print_stderr(msg):
    """Print out to stderr."""
    sys.stderr.write(msg + '\n')


def wrap_line(instr):
    """Wrap a string into several lines."""
    step = 50
    outstr = ''
    pos = 0
    while (pos + step) <= len(instr):
        outstr = outstr + instr[pos:pos + step] + r'\l'
        pos = pos + step

    outstr = outstr + instr[pos:] + r'\l'

    return outstr

# -------------------------------------------------------------------------------


class Recorder(object):

    """Recorder class is responsible for record status information and write it to file."""

    file_name = ''
    outf = file
    mypid = str(os.getpid())
    store = []
    parsed_store = []
    inodes = {}  # inodes[inode] = filename

    STATE_ID_SECTION = 'state_id'
    STATE_NAME_SECTION = 'state_name'
    FILE_SECTION = 'file'
    UNIX_SECTION = 'unix'
    TCP_SECTION = 'tcp'
    PS_SECTION = 'ps'
    INODES = 'inodes'

    UNIX_CMD = "ss state established -n -xp  -o | sed -e '1d' | sed -e 's/\"//g'"
    TCP_CMD = "ss state established -n -tp  -o | sed -e '1d' | sed -e 's/\"//g' | sed -e 's/timer:([^)]*)//'"
    PS_CMD = "ps --no-headers -e -o pid,ppid,comm,command"
    FILE_CMD = "lsof -n -P -FLuPtfinc0"

    def __init__(self, fn):
        """Initialization."""
        self.file_name = fn

    def write_section(self, i, section_name, section):
        """Write out one section to outf."""
        self.outf.write('#### step ' + str(i) + ' ' + section_name + '\n')
        self.outf.write(section)
        self.outf.write('\n')

    def record(self):
        """Build list that includes output of commands for each iteration.

        list = [ State(state_name, file_out, unix_out, tcp_out, ps_out), ... ]
        """
        state_name = '-initial-'

        iteration = 0
        while 1:

            sys.stdout.write('Capturing ' + str(iteration) + '. state information...\n')

            state = dict()

            state[self.STATE_ID_SECTION] = str(iteration)
            state[self.STATE_NAME_SECTION] = state_name
            state[self.FILE_SECTION] = get_stdout(self.FILE_CMD)
            state[self.UNIX_SECTION] = get_stdout(self.UNIX_CMD)
            state[self.TCP_SECTION] = get_stdout(self.TCP_CMD)
            state[self.PS_SECTION] = get_stdout(self.PS_CMD)

            self.store.append(state)

            iteration += 1
            state_name = raw_input(str(iteration) + ". state, enter state name: ")
            if state_name == "":
                break

    def write_to_disk(self):
        """Write store to disk."""
        try:
            self.outf = open(self.file_name, 'w')
        except IOError as exception:
            print_stderr("I/O error({0}): {1} - {2}".format(exception.errno, self.file_name, exception.strerror))
            exit(1)

        self.outf.write(str(self.mypid))
        self.outf.write('\n')

        for i in range(len(self.store)):
            self.write_section(i, self.STATE_ID_SECTION, self.store[i][self.STATE_ID_SECTION])
            self.write_section(i, self.STATE_NAME_SECTION, self.store[i][self.STATE_NAME_SECTION])
            self.write_section(i, self.FILE_SECTION, self.store[i][self.FILE_SECTION])
            self.write_section(i, self.UNIX_SECTION, self.store[i][self.UNIX_SECTION])
            self.write_section(i, self.TCP_SECTION, self.store[i][self.TCP_SECTION])
            self.write_section(i, self.PS_SECTION, self.store[i][self.PS_SECTION])

        self.outf.close()
        sys.stdout.write(self.file_name + ' is created.\n')

    def load_from_disk(self):
        """Load data from disk."""
        outstr = ''
        section = ''
        state_number = ''

        state = dict()

        try:
            inf = open(self.file_name, 'r')
        except IOError as exception:
            print_stderr("I/O error({0}): {1} - {2}".format(exception.errno, self.file_name, exception.strerror))
            exit(1)

        # first is used as a flag to find the 1st line in the file that
        # contains the pid of the script
        first = True
        for line in inf:
            if first:
                self.mypid = line.strip()
                first = False
                continue

            if line.find('####', 0) >= 0:
                tokens = line.split()
                assert len(tokens) == 4

                if section != '':
                    state[section] = outstr
                    outstr = ''

                section = tokens[3]

                new_state_number = tokens[2]
                if new_state_number != state_number and state_number != '':
                    self.store.append(state)
                    state = dict()

                state_number = new_state_number
            else:
                outstr += line

        # End of file, we have to add the last section
        if section != '':
            state[section] = outstr
        self.store.append(state)

    def parse(self):
        """Parse input."""
        self.parsed_store = []

        for i in range(0, len(self.store), 1):
            LOG.debug(self.store[i][Recorder.STATE_NAME_SECTION])

            parsed = dict()
            processes = gen_ps_data(self.store[i][Recorder.PS_SECTION])

            parsed[Recorder.PS_SECTION] = processes
            parsed[Recorder.FILE_SECTION], parsed[Recorder.INODES] = gen_file_data(processes, self.store[i][Recorder.FILE_SECTION])
            parsed[Recorder.UNIX_SECTION] = gen_unix_data(processes, self.store[i][Recorder.UNIX_SECTION])
            parsed[Recorder.TCP_SECTION] = gen_tcp_data(processes, self.store[i][Recorder.TCP_SECTION])

            self.parsed_store.append(parsed)

# --------------------------------------------------------------------------------


class Graph(object):

    """Create graph."""

    inodes = {}  # inodes[inode] = filename
    title = ''
    file_name = ''
    mygraph = None
    mymaingraph = None
    mygraphs = []
    MYGRAPH = 'mygraph'

    processes = None
    recorder = None

    pre_str = """< <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">

    <TR>
        <TD COLSPAN="2"><B>Legend</B></TD>
    </TR>

    <TR>
        <TD>TCP</TD>
        <TD ALIGN="left" ><FONT COLOR="red">red line</FONT></TD>
    </TR>

    <TR>
        <TD>Unix</TD>
        <TD ALIGN="left" ><FONT COLOR="blue">blue line</FONT></TD>
    </TR>

    <TR>
        <TD>Pipe</TD>
        <TD ALIGN="left" ><FONT COLOR="green">green line</FONT></TD>
    </TR>

    <TR>
        <TD>Shared memory</TD>
        <TD ALIGN="left" ><FONT COLOR="purple">purple line</FONT></TD>
    </TR>

    <TR>
        <TD>Fork</TD>
        <TD ALIGN="left" ><FONT COLOR="black">black line</FONT></TD>
    </TR>
    """

    state_str = """
    <TR>
    <TD>(%d)</TD>
    <TD ALIGN="left" >%s</TD>
    </TR>
    """
    post_str = """</TABLE> >"""

    def __init__(self, recorder, title, file_name):
        """Initializer."""
        self.recorder = recorder
        self.title = title
        self.file_name = file_name
        self.mygraph = gv.AGraph(strict=False, directed=True, label=title, labelloc='t')

    def visualize(self, index):
        """Visualize the store."""
        # Maybe this shall be moved to constructor
        self.recorder.parse()

        self.ps_graph(index)
        self.unix_graph(index)
        self.file_graph(index)
        self.tcp_graph(index)
        self.legend()

    def legend(self):
        """Draw legend."""
        lgraph = self.mygraph.add_subgraph(name='LegendGraph', rank='sink')
        lgraph.add_node('Legend')
        legend = lgraph.get_node('Legend')

        states = ''
        for i in range(1, len(self.recorder.store)):
            value = self.recorder.store[i]
            states = states + self.state_str % (i, value[Recorder.STATE_NAME_SECTION])

        legend.attr.update(shape='none', margin='0', label=self.pre_str + states + self.post_str)

    def diff(self, parsed, section, index):
        """Diff."""
        data = {}
        assert index > 0
        for key, value in parsed[index][section].items():
            processes = parsed[index][Recorder.PS_SECTION]
            for i in range(index - 1, -1, -1):
                if key in parsed[i][section]:
                    continue
                else:
                    # LOG.debug('Element is new in state ' + str(i + 1) + ' and value is ' + str(key) + ' ' + str(processes[key]))
                    if self.check_parent(key, processes):
                        data[key] = (str(i + 1), value)
                    break

        return data

    def ps_graph(self, index):
        """Generate ps graph."""
        parsed = self.recorder.parsed_store
        data = self.diff(parsed, Recorder.PS_SECTION, index)

        # Print edges
        for value in data.values():
            state = value[0]
            process_child = value[1]
            processes = parsed[int(state)][Recorder.PS_SECTION]
            process_parent = processes[process_child.ppid]
            self.add_ps_edge2(process_parent, process_child, state)

    def file_graph(self, index):
        """File graph generation."""
        parsed = self.recorder.parsed_store
        raw = self.diff(parsed, Recorder.FILE_SECTION, index)
        data = self.filter_files(raw)

        # Add edges
        for key, value in data.items():
            files = value[1]
            set_value = set(files)
            # We only draw edges between processes
            if len(set_value) > 1:
                for process in set_value:
                    self.add_file_edge(key, process, index)

    def unix_graph(self, index):
        """Generate unix graph."""
        parsed = self.recorder.parsed_store
        data = self.diff(parsed, Recorder.UNIX_SECTION, index)

        # This way we show only one edge beteen processes
        final_data = data
        # final_data = set()
        # for value in data.values():
        #     final_data.add(tuple(sorted(value)))

        for value in final_data.values():
            state = value[0]
            processes = value[1]
            # print 'processes=', processes, 'state=', state
            # unix socket is always between two processes or to the very same process
            assert len(processes) == 1 or len(processes) == 2

            process1 = processes[0]
            if len(processes) == 2:
                process2 = processes[1]
            else:
                # Why we need this?
                process2 = ProcessRecord(process1.process_name, process1.pid, None, None)

            # Filter out unix sockets to the very same process
            if process1.pid != process2.pid:
                LOG.debug("    " + process1.pid + " -> " + process2.pid + " [label=\"(" + state + ")\"]" + "\n")
                processes = parsed[int(state)][Recorder.PS_SECTION]
                self.add_unix_edge2(process1, process2, processes, state)

    def tcp_graph(self, index):
        """Generate TCP graph."""
        parsed = self.recorder.parsed_store
        data = self.diff(parsed, Recorder.TCP_SECTION, index)

        # Print edges
        for key, value in data.items():
            state = value[0]
            myvalue = value[1]
            assert len(myvalue) == 1 or len(myvalue) == 2

            process1 = myvalue[0]
            # If the other end of the tcp sockect is a remote process (on a remote host) then we can not
            # simply create the ProcessRecord. We simply show the process name and the key of the local process:
            if len(myvalue) == 2:
                process2 = myvalue[1]
            else:
                process2 = ProcessRecord(process1.process_name, "\"" + key + "\"", None, None)

            processes = parsed[int(state)][Recorder.PS_SECTION]
            # Filter out tcp sockets to the very same process
            if process1.pid != process2.pid:
                self.add_tcp_edge(processes, process1, process2, state)

    def check_parent(self, pid, processes):
        """Recursive function to check parent."""
        if pid not in processes:
            return True

        ppid = processes[pid].ppid
        if ppid == '1':
            return True

        if ppid == self.recorder.mypid:
            return False

        return self.check_parent(ppid, processes)

    def filter_files(self, files):
        """Filter out files.

        Filter out any file that is connected directly or indirectly with the
        recorder python process
        """
        inodes_to_be_deleted = []
        cpy = files.copy()  # To have all inodes as we will remove elements from files

        for inode in cpy.keys():

            process_record_list = files[inode][1]

            for process_record in process_record_list:
                if process_record.pid == self.recorder.mypid:
                    inodes_to_be_deleted.append(inode)
                    self.check_file(files, process_record.pid, inode, inodes_to_be_deleted)

        for inode in inodes_to_be_deleted:
            LOG.debug("deleting -----" + ' ' + inode + ' ' + str(files[inode]))
            del files[inode]

        return files

    #  {inode4}[ ProcessRecord(process_name4, pid4, ppid4), ProcessRecord(spvis, mypid !!!, ppid2), ... ]
    #                                          ^
    #                                          |
    #                                          |
    #  {inode3}[ ProcessRecord(process_name4, pid4, ppid4), ProcessRecord(process_name2, pid2, ppid2), ... ]
    #                                                                                     ^
    #                                                                                     |
    #                                                                                     |
    #  {inode1}[ ProcessRecord(process_name1, pid1, ppid1), ProcessRecord(process_name2, pid2, ppid2), ... ]
    #                                          |
    #                                          |
    #                                          V
    #  {inode2}[ ProcessRecord(process_name1, pid1, ppid1), ProcessRecord(process_name3, pid3, ppid3), ... ]
    def check_file(self, data, from_pid, inode, inodes_to_be_deleted):
        """Check file."""
        LOG.debug("#>" + ' ' + inode + ' ' + str(data[inode]))

        process_record_list = data[inode][1]
        for process_record in process_record_list:
            if process_record.pid == from_pid:
                continue

            for i in data.keys():
                if process_record in data[i][1] and i not in inodes_to_be_deleted:
                    inodes_to_be_deleted.append(i)
                    self.check_file(data, process_record.pid, i, inodes_to_be_deleted)

    def add_file_edge(self, key, process, index):
        """Add file edge to graph."""
        # assert not '127.0.0' in key

        self.mygraph.add_edge(key, process.pid)
        edge = self.mygraph.get_edge(key, process.pid)
        inodes = self.recorder.parsed_store[index][Recorder.INODES]
        if inodes[key][FILE_NAME].startswith(SHMEM_FILENAME):
            edge.attr.update(label="(" + str(index) + ")", dir='none', color='purple')
        else:
            edge.attr.update(label="(" + str(index) + ")", dir='none', color='green')

        node1 = self.mygraph.get_node(key)
        node1.attr.update(label='File' + "\\n" + str(inodes[key]), fontsize='8', width='0.01', height='0.01', shape='note')
        processes = self.recorder.parsed_store[index][Recorder.PS_SECTION]
        if process.pid in processes:
            command = processes[process.pid].command
        else:
            command = '<empty>'
        node2 = self.mygraph.get_node(process.pid)
        node2.attr.update(label=process.process_name + "\\n" + 'pid=' + process.pid + "\\n" + command)

    def add_unix_edge(self, process1, process2, state_id):
        """Add unix edge to graph."""
        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", dir='none', color='blue')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid + "\\n" + self.processes[process1.pid].command)
        node2 = self.mygraph.get_node(process2.pid)
        node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid + "\\n" + self.processes[process2.pid].command)

    def add_unix_edge2(self, process1, process2, processes, state_id):
        """Add unix edge to graph."""
        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", dir='none', color='blue')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid + "\\n" + processes[process1.pid].command)
        node2 = self.mygraph.get_node(process2.pid)
        node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid + "\\n" + processes[process2.pid].command)

    def add_tcp_edge(self, processes, process1, process2, state_id):
        """Add unix edge to graph."""
        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", dir='none', color='red')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid + "\\n" + processes[process1.pid].command)
        node2 = self.mygraph.get_node(process2.pid)
        if ':' in process2.pid:
            node2.attr.update(label='remote=' + process2.pid)
        else:
            node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid + "\\n" + processes[process2.pid].command)

    def add_ps_edge2(self, process1, process2, state_id):
        """Add unix edge to graph."""
        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", color='black')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid + "\\n" + process1.command)
        node2 = self.mygraph.get_node(process2.pid)
        node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid + "\\n" + process2.command)

    def add_ps_edge(self, process1, process2, state_id):
        """Add unix edge to graph."""
        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", color='black')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid + "\\n")  # + self.processes[process1.pid].command)
        node2 = self.mygraph.get_node(process2.pid)
        node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid + "\\n")  # + self.processes[process2.pid].command)

    def write(self, index):
        """Write out graph to disk."""
        name = self.recorder.store[index][Recorder.STATE_NAME_SECTION].strip()
        complete_file_name = 'out.' + str(index) + '.' + name + '.' + self.file_name

        try:
            self.mygraph.draw(complete_file_name, prog="dot")
        except IOError as exception:
            print_stderr(str(exception))
            exit(1)

        sys.stdout.write(complete_file_name + ' is created.\n')

    def gen_file_data(self, fulllist, mystr):
        """Generate file data."""
        data = {}  # data[inode] = [ ProcessRecord(process_name, pid, ppid) ]

        lines = mystr.split('\n')
        for line in lines:
            fields = line.strip('\x00').split('\x00')
            field_map = {}
            for field in fields:
                if len(field) < 2:
                    continue
                field_map[field[0]] = field[1:]

            if len(field_map) > 0:

                if PROCESS_PID in field_map:
                    # Just remember we will see from here files for a new process
                    process_map = field_map

                    # lsof gives back the thread name instead of the command name
                    # let's fix that by looking up the command name from ps list
                    pid = process_map[PROCESS_PID]
                    if pid in fulllist:
                        process = ProcessRecord(fulllist[pid].process_name, pid, None, None)
                    else:
                        process = ProcessRecord(process_map[PROCESS_NAME], pid, None, None)

                else:

                    if (
                            'IP' in field_map[FILE_TYPE] or
                            'unix' in field_map[FILE_TYPE] or
                            # /SYSV indicates shared memory we want to show
                            ('REG' in field_map[FILE_TYPE] and not field_map[FILE_NAME].startswith(SHMEM_FILENAME)) or
                            field_map[FILE_NAME].endswith('.so') or
                            INODE_NUMBER not in field_map):
                        continue

                    self.inodes[field_map[INODE_NUMBER]] = field_map
                    if not field_map[INODE_NUMBER] in data:
                        data[field_map[INODE_NUMBER]] = []

                    data[field_map[INODE_NUMBER]].append(process)

        return data

# --------------------------------------------------------------------------------


def gen_file_data(processes, mystr):
    """Generate file data."""
    data = {}  # data[inode] = [ ProcessRecord(process_name, pid, ppid) ]
    inodes = {}  # inodes[inode] = {key:value}

    lines = mystr.split('\n')
    for line in lines:
        fields = line.strip('\x00').split('\x00')
        field_map = {}
        for field in fields:
            if len(field) < 2:
                continue
            field_map[field[0]] = field[1:]

        if len(field_map) > 0:

            if PROCESS_PID in field_map:
                # Just remember we will see from here files for a new process
                process_map = field_map

                # lsof gives back the thread name instead of the command name
                # let's fix that by looking up the command name from ps list
                pid = process_map[PROCESS_PID]
                if pid in processes:
                    process = processes[pid]
                else:
                    process = ProcessRecord(process_map[PROCESS_NAME], pid, None, None)

            else:

                if (
                        'IP' in field_map[FILE_TYPE] or
                        'unix' in field_map[FILE_TYPE] or
                        # /SYSV indicates shared memory we want to show
                        ('REG' in field_map[FILE_TYPE] and not field_map[FILE_NAME].startswith(SHMEM_FILENAME)) or
                        field_map[FILE_NAME].endswith('.so') or
                        INODE_NUMBER not in field_map):
                    continue

                inodes[field_map[INODE_NUMBER]] = field_map
                if not field_map[INODE_NUMBER] in data:
                    data[field_map[INODE_NUMBER]] = []

                data[field_map[INODE_NUMBER]].append(process)

    return data, inodes


def gen_data(processes, inputstr, local_pos, peer_pos, users_pos):
    """Generate data."""
    data = {}
    for line in inputstr.splitlines():
        # print line
        line_array = line.split()

        if not line_array:
            continue

        local_addr = line_array[local_pos]
        peer_addr = line_array[peer_pos]

        # If server side created a IPv6 server socket but the client connected with an IPv4 socket then
        # in ss command output for the server socket ::ffff:a.b.c.d:port, while for the client a.b.c.d:port
        # will be indicated. In order to be able to match them we shall remove the '::ffff:' prefix:
        if local_addr.startswith('::ffff:'):
            local_addr = local_addr[7:]
        if peer_addr.startswith('::ffff:'):
            peer_addr = peer_addr[7:]

        if len(line_array) > users_pos:
            users = line_array[users_pos]
            u_a = users.split(',')

            if u_a[1][0] == 'p':
                pidpos = 4  # Ubuntu
            else:
                pidpos = 0  # Debian

            local_pid = u_a[1][pidpos:]
            n_a = u_a[0].split("((")
            local_name = n_a[1]
        else:
            # This shows that line from 'ss' does not include information on processes
            local_pid = "-1"
            local_name = "<empty>2"

        key = local_addr + "\\n" + peer_addr if local_addr < peer_addr else peer_addr + "\\n" + local_addr

        if key not in data:
            data[key] = []

        if local_pid != "-1":
            process = ProcessRecord(local_name, local_pid, processes[local_pid].ppid, processes[local_pid].command)
        else:
            process = ProcessRecord(local_name, local_pid, local_pid, local_name)

        data[key].append(process)

    return data

# --------------------------------------------------------------------------------


def gen_tcp_data(processes, mystr):
    """Both unix & tcp uses ss to retrive data, hence same structure - same parsing."""
    return gen_data(processes, mystr, 2, 3, 4)

# --------------------------------------------------------------------------------


def gen_unix_data(processes, mystr):
    """Both unix & tcp uses ss to retrive data, hence same structure - same parsing."""
    return gen_data(processes, mystr, 4, 6, 7)

# --------------------------------------------------------------------------------


def gen_ps_data(mystr):
    """Generate ps data."""
    pid_pos = 0
    ppid_pos = 1
    name_pos = 2

    data = {}
    for line in mystr.splitlines():
        line_array = line.split(None, 3)
        if len(line_array) < 1:
            continue

        pid = line_array[pid_pos]
        ppid = line_array[ppid_pos]
        process_name = line_array[name_pos]
        command = line_array[name_pos + 1:][0]

        data[pid] = ProcessRecord(process_name, pid, ppid, wrap_line(command))

    return data

# --------------------------------------------------------------------------------


def dict_diff(old, new):
    """Dictionary diff."""
    data = {}
    for key, value in new.items():
        if key not in old:
            data[key] = value

    return data

# --------------------------------------------------------------------------------


def main():
    """The main function."""
    args = cmdparser()
    if args.version:
        print_stderr('ipcvis v0.2')
        exit(0)

    recorder = Recorder(args.file)

    if not (args.record or args.load):
        if not args.noroot:
            check_root()
        recorder.record()
        recorder.write_to_disk()
        graph = Graph(recorder, args.title, args.out)
        graph.visualize(1)
        graph.write(args.out)
    else:
        if args.record:
            if not args.noroot:
                check_root()
            recorder.record()
            recorder.write_to_disk()

        elif args.load:
            recorder.load_from_disk()
            for i in range(1, len(recorder.store)):
                name = recorder.store[i][Recorder.STATE_NAME_SECTION].strip()
                graph = Graph(recorder, args.title + ' - ' + name + ' (' + str(i) + ')', args.out)
                # graph = Graph(recorder, args.title, args.out)
                graph.visualize(i)
                graph.write(i)
        else:
            print_stderr('Should not get here...')
            exit(1)

# --------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
