#! /usr/bin/env python
'''ipcvis - visualize inter-process communication. Small script that is able to create
graph of verious IPC communication channels between processes, together with their process hierarchy'''

#--------------------------------------------------------------------------------
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
#--------------------------------------------------------------------------------

import os
import sys
import subprocess
import argparse
import logging

import pygraphviz as gv

from collections import namedtuple

#--------------------------------------------------------------------------------

ProcessRecord = namedtuple('ProcessRecord', 'process_name pid ppid')

#-------------------------------------------------------------------------------
# Utilities
#-------------------------------------------------------------------------------

def check_root():
    '''Check if user running this script is root.'''

    if os.geteuid() != 0:
        msg = '''You do not have root privileges.
Without root privileges this program is not able to retrieve all needed system details.
Exiting...'''

        exit(msg)

def get_stdout(cmd):
    '''Returns stdout of cmd.'''

    fnull = open(os.devnull, 'w')
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=fnull).stdout
    return pipe.read()


def cmdparser():
    '''Responsible for parsing command line arguments'''

    parser = argparse.ArgumentParser(description='This program records inter-process communication details and visualize them.')
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('-v', '--version', help='show version information', action='store_true')
    parser.add_argument('-n', '--noroot', help='does not check for root privileges', action='store_true')
    group.add_argument('-r', "--record", help='record', action='store_true')
    group.add_argument('-l', "--load", help='load', action='store_true')
    parser.add_argument('-t', '--title', help='diagram title (default: %(default)s)', default='IPC visualization')
    parser.add_argument('-f', '--file', help='record file (default: %(default)s)', default='ipcvis.ipcdump')
    parser.add_argument('-o', '--out', help='output file for rendering (default: %(default)s)', default='ipcvis.ps')

    return parser.parse_args()

#-------------------------------------------------------------------------------

class Recorder(object):
    '''Recorder class is responsible for record status information and write it to file.'''

    file_name = ''
    outf = file
    mypid = str(os.getpid())
    store = []

    STATE_ID_SECTION = 'state_id'
    STATE_NAME_SECTION = 'state_name'
    PIPE_SECTION = 'pipe'
    UNIX_SECTION = 'unix'
    TCP_SECTION = 'tcp'
    PS_SECTION = 'ps'

    UNIX_CMD = "ss state established -n -xp  -o | sed -e '1d' | sed -e 's/\"//g'"
    TCP_CMD = "ss state established -n -tp  -o | sed -e '1d' | sed -e 's/\"//g' | sed -e 's/timer:([^)]*)//'"
    PS_CMD = "ps --no-headers -e -o pid,ppid,comm"
    PIPE_CMD = "lsof -n | grep FIFO"

    def __init__(self, fn):
        self.file_name = fn

    def write_section(self, i, section_name, section):
        '''Writes out one section to outf.'''
        self.outf.write('#### step ' + str(i) + ' ' + section_name + '\n')
        self.outf.write(section)
        self.outf.write('\n')

    def record(self):
        '''Builds list that includes output of commands for each iteration.
        list = [ State(state_name, pipe_out, unix_out, tcp_out, ps_out), ... ]
        '''
        state_name = '-initial-'

        iteration = 0
        while 1:

            sys.stdout.write('Capturing ' + str(iteration) + '. state information...\n')

            state = dict()

            state[self.STATE_ID_SECTION] = str(iteration)
            state[self.STATE_NAME_SECTION] = state_name
            state[self.PIPE_SECTION] = get_stdout(self.PIPE_CMD)
            state[self.UNIX_SECTION] = get_stdout(self.UNIX_CMD)
            state[self.TCP_SECTION] = get_stdout(self.TCP_CMD)
            state[self.PS_SECTION] = get_stdout(self.PS_CMD)

            self.store.append(state)

            iteration += 1
            state_name = raw_input(str(iteration) + ". state, enter state name: ")
            if state_name == "":
                break

    def write_to_disk(self):
        '''Writes store to disk'''

        try:
            self.outf = open(self.file_name, 'w')
        except IOError as exception:
            sys.stderr.write("I/O error({0}): {1} - {2}\n".format(exception.errno, self.file_name, exception.strerror))
            exit(1)

        self.outf.write(str(self.mypid))
        self.outf.write('\n')

        for i in range(len(self.store)):
            self.write_section(i, self.STATE_ID_SECTION, self.store[i][self.STATE_ID_SECTION])
            self.write_section(i, self.STATE_NAME_SECTION, self.store[i][self.STATE_NAME_SECTION])
            self.write_section(i, self.PIPE_SECTION, self.store[i][self.PIPE_SECTION])
            self.write_section(i, self.UNIX_SECTION, self.store[i][self.UNIX_SECTION])
            self.write_section(i, self.TCP_SECTION, self.store[i][self.TCP_SECTION])
            self.write_section(i, self.PS_SECTION, self.store[i][self.PS_SECTION])

        self.outf.close()
        sys.stdout.write(self.file_name + ' is created.\n')

    def load_from_disk(self):
        '''Loads data from disk'''

        outstr = ''
        section = ''
        state_number = ''

        state = dict()

        try:
            inf = open(self.file_name, 'r')
        except IOError as exception:
            sys.stderr.write("I/O error({0}): {1} - {2}\n".format(exception.errno, self.file_name, exception.strerror))
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

#--------------------------------------------------------------------------------

class Graph(object):
    '''Create graph'''

    mygraph = None

    processes = None
    recorder = None

    pre_str = '''< <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">

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
        <TD>Fork</TD>
        <TD ALIGN="left" ><FONT COLOR="black">black line</FONT></TD>
    </TR>
    '''

    state = '''
    <TR>
    <TD>(%d)</TD>
    <TD ALIGN="left" >%s</TD>
    </TR>
    '''
    post_str = '''</TABLE> >'''

    def __init__(self, recorder, title):
        self.recorder = recorder
        self.mygraph = gv.AGraph(strict=False, directed=True, label=title, labelloc='t')

    def visualize(self):
        '''This function visualize the store.'''

        for i in range(1, len(self.recorder.store), 1):
            logging.debug(self.recorder.store[i][Recorder.STATE_NAME_SECTION])

            previous = self.recorder.store[i - 1]
            now = self.recorder.store[i]

            state_id = now[Recorder.STATE_ID_SECTION].strip()

            self.ps_graph(previous[Recorder.PS_SECTION], now[Recorder.PS_SECTION], state_id)
            self.pipe_graph(previous[Recorder.PIPE_SECTION], now[Recorder.PIPE_SECTION], state_id)
            self.unix_graph(previous[Recorder.UNIX_SECTION], now[Recorder.UNIX_SECTION], state_id)
            self.tcp_graph(previous[Recorder.TCP_SECTION], now[Recorder.TCP_SECTION], state_id)

        lgraph = self.mygraph.add_subgraph(name='LegendGraph', rank='sink')
        lgraph.add_node('Legend')
        legend = lgraph.get_node('Legend')

        states = ''
        for i in range(len(self.recorder.store)):
            value = self.recorder.store[i]
            states = states + self.state % (i, value[Recorder.STATE_NAME_SECTION])

        legend.attr.update(shape='none', margin='0', label=self.pre_str + states + self.post_str)
        return

    def ps_graph(self, before, after, state_id):
        '''Generate ps graph'''

        old_processes = gen_ps_data(before)
        self.processes = gen_ps_data(after)

        data = self.diff(old_processes, self.processes)

        logging.debug(self.processes)

        # Print edges
        for value in data.values():
            self.add_ps_edge(self.processes[value.ppid], value, state_id)

        return self.processes

    def pipe_graph(self, before, after, state_id):
        '''Pipe graph generation'''

        raw = dict_diff(gen_pipe_data(self.processes, before), gen_pipe_data(self.processes, after))
        data = self.filter_pipes(raw)

        # Add edges
        for key, value in data.items():

            set_value = set(value)
            # We only draw edges between processes
            if len(set_value) > 1:
                for process in set(value):
                    self.add_pipe_edge(key, process, state_id)

    def unix_graph(self, before, after, state_id):
        '''Generate unix graph'''

        data = self.diff(gen_unix_data(before), gen_unix_data(after))

        # Print edges

        # This way we show only one edge beteen processes
        final_data = set()
        for value in data.values():
            final_data.add(tuple(sorted(value)))

        for value in final_data:
            assert len(value) == 1 or len(value) == 2

            process1 = value[0]
            if len(value) == 2:
                process2 = value[1]
            else:
                process2 = ProcessRecord(process1.process_name, process1.pid, None)

            # Filter out unix sockets to the very same process
            if process1.pid != process2.pid:
                logging.debug("    " + process1.pid + " -> " + process2.pid + " [label=\"(" + state_id + ")\"]" + "\n")
                self.add_unix_edge(process1, process2, state_id)


    def tcp_graph(self, before, after, state_id):
        '''Generate TCP graph'''

        data = self.diff(gen_tcp_data(before), gen_tcp_data(after))

        # Print edges
        for key, value in data.items():
            assert len(value) == 1 or len(value) == 2

            process1 = value[0]
            # If the other end of the tcp sockect is a remote process (on a remote host) then we can not
            # simply create the ProcessRecord. We simply show the process name and the key of the local process:
            if len(value) == 2:
                process2 = value[1]
            else:
                process2 = ProcessRecord(process1.process_name, "\"" + key + "\"", None)

            # Filter out tcp sockets to the very same process
            if process1.pid != process2.pid:
                self.add_tcp_edge(process1, process2, state_id)

    def diff(self, old, new):
        '''Create diff of two dicts by their keys. Also remove anything that is
        children of the recorder python process'''

        data = {}
        for pid, value in new.items():
            if not pid in old:
                # Doing the best to filter out things we are not interested in:
                # This will filter out anything related to the recorder python process
                # and its children
                if self.check_parent(pid):
                    data[pid] = value

        return data

    def check_parent(self, pid):
        '''Recursive function to check parent'''

        if pid not in self.processes:
            return True

        ppid = self.processes[pid].ppid
        if ppid == '1':
            return True

        if ppid == self.recorder.mypid:
            return False

        return self.check_parent(ppid)

    def filter_pipes(self, pipes):
        '''Filter out any pipe that is connected directly or indirectly with the
        recorder python process'''

        inodes_to_be_deleted = []
        cpy = pipes.copy() # To have all inodes as we will remove elements from pipes

        for inode in cpy.keys():

            process_record_list = pipes[inode]

            for process_record in process_record_list:
                if process_record.pid == self.recorder.mypid:
                    inodes_to_be_deleted.append(inode)
                    self.check_pipe(pipes, process_record.pid, inode, inodes_to_be_deleted)

        for inode in inodes_to_be_deleted:
            logging.debug("deleting -----" + ' ' + inode + ' ' + str(pipes[inode]))
            del pipes[inode]

        return pipes

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
    def check_pipe(self, data, from_pid, inode, inodes_to_be_deleted):
        '''Check pipe'''

        logging.debug("#>" + ' ' + inode + ' ' + str(data[inode]))

        process_record_list = data[inode]
        for process_record in process_record_list:
            if process_record.pid == from_pid:
                continue

            for i in data.keys():
                if process_record in data[i] and not i in inodes_to_be_deleted:
                    inodes_to_be_deleted.append(i)
                    self.check_pipe(data, process_record.pid, i, inodes_to_be_deleted)

    def add_pipe_edge(self, key, process, state_id):
        '''Add pipe edge to graph'''

        self.mygraph.add_edge(key, process.pid)
        edge = self.mygraph.get_edge(key, process.pid)
        edge.attr.update(label="(" + state_id + ")", dir='none', color='green')

        node1 = self.mygraph.get_node(key)
        node1.attr.update(label='inode' + "\\n" + key, fontsize='8', width='0.01', height='0.01', shape='note')

        node2 = self.mygraph.get_node(process.pid)
        node2.attr.update(label=process.process_name + "\\n" + 'pid=' + process.pid)


    def add_unix_edge(self, process1, process2, state_id):
        '''Add unix edge to graph'''

        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", dir='none', color='blue')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid)
        node2 = self.mygraph.get_node(process2.pid)
        node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid)

    def add_tcp_edge(self, process1, process2, state_id):
        '''Add unix edge to graph'''

        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", dir='none', color='red')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid)
        node2 = self.mygraph.get_node(process2.pid)
        if  ':' in process2.pid:
            node2.attr.update(label='remote=' + process2.pid)
        else:
            node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid)

    def add_ps_edge(self, process1, process2, state_id):
        '''Add unix edge to graph'''

        self.mygraph.add_edge(process1.pid, process2.pid)
        edge = self.mygraph.get_edge(process1.pid, process2.pid)
        edge.attr.update(label="(" + state_id + ")", color='black')
        node1 = self.mygraph.get_node(process1.pid)
        node1.attr.update(label=process1.process_name + "\\n" + 'pid=' + process1.pid)
        node2 = self.mygraph.get_node(process2.pid)
        node2.attr.update(label=process2.process_name + "\\n" + 'pid=' + process2.pid)

    def write(self, file_name):
        '''Write out graph to disk'''
        #self.mygraph.write('teszt.dot')
        try:
            self.mygraph.draw(file_name, prog="dot")
        except IOError as exception:
            sys.stderr.write(str(exception))
            exit(1)

        sys.stdout.write(file_name + ' is created.\n')

#--------------------------------------------------------------------------------

def gen_data(inputstr, local_pos, peer_pos, users_pos):
    '''Generates data'''

    data = {}

    for line in inputstr.splitlines():
        line_array = line.split()

        if not line_array:
            continue

        local_addr = line_array[local_pos]
        peer_addr = line_array[peer_pos]

        if len(line_array) > users_pos:
            users = line_array[users_pos]
            u_a = users.split(',')
            local_pid = u_a[1][4:]
            n_a = u_a[0].split("((")
            local_name = n_a[1]
        else:
            local_pid = "-1"
            local_name = "<empty>"

        key = local_addr + "\\n" + peer_addr if local_addr < peer_addr else peer_addr + "\\n" + local_addr

        if not key in data:
            data[key] = []

        data[key].append(ProcessRecord(local_name, local_pid, None))

    return data

#--------------------------------------------------------------------------------

def gen_tcp_data(mystr):
    '''Both unix & tcp uses ss to retrive data, hence same structure - same parsing'''
    return gen_data(mystr, 2, 3, 4)

#--------------------------------------------------------------------------------

def gen_unix_data(mystr):
    '''Both unix & tcp uses ss to retrive data, hence same structure - same parsing'''
    return gen_data(mystr, 4, 6, 7)

#--------------------------------------------------------------------------------

def gen_ps_data(mystr):
    '''Generate ps data'''

    pid_pos = 0
    ppid_pos = 1
    name_pos = 2

    data = {}
    for line in mystr.splitlines():
        line_array = line.split()
        if len(line_array) < 1:
            continue

        pid = line_array[pid_pos]
        ppid = line_array[ppid_pos]
        process_name = line_array[name_pos]

        data[pid] = ProcessRecord(process_name, pid, ppid)

    return data

#--------------------------------------------------------------------------------

def gen_pipe_data(fulllist, mystr):
    '''Generate pipe data'''

    data = {} # data[inode] = [ ProcessRecord(process_name, pid, ppid) ]
    for line in mystr.splitlines():
        line_array = line.split()
        if len(line_array) < 1:
            continue

        process_name = line_array[0]
        pid = line_array[1]
        #ppid   = line_array[2] 2 is Task ID, for PPID we have to use -R for lsof

        alength = len(line_array)
        assert alength == 10 or alength == 9
        inode = line_array[8 if (alength == 10) else 7]

        if not inode in data:
            data[inode] = []

        # lsof gives back the thread name instead of the command name
        # let's fix that by looking up the command name from ps list
        if fulllist.has_key(pid):
            process = ProcessRecord(fulllist[pid].process_name, pid, None)
        else:
            process = ProcessRecord(process_name, pid, None)

        data[inode].append(process)

    return data

#--------------------------------------------------------------------------------

def dict_diff(old, new):
    '''Dictionary diff'''

    data = {}
    for key, value in new.items():
        if not key in old:
            data[key] = value

    return data

#--------------------------------------------------------------------------------

def main():
    '''The main function'''

    args = cmdparser()
    if args.version:
        sys.stderr.write('ipcvis v0.1\n')
        exit(0)

    recorder = Recorder(args.file)

    if len(sys.argv) == 1:
        if not args.noroot:
            check_root()
        recorder.record()
        recorder.write_to_disk()
        graph = Graph(recorder, args.title)
        graph.visualize()
        graph.write(args.out)
    else:
        if args.record:
            if not args.noroot:
                check_root()
            recorder.record()
            recorder.write_to_disk()

        elif args.load:
            recorder.load_from_disk()
            graph = Graph(recorder, args.title)
            graph.visualize()
            graph.write(args.out)
        else:
            sys.stderr.write('Should not get here...\n')
            exit(1)

#--------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
