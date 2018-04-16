#!/usr/bin/python3

###############################################################################
### This script is a wrapper for hashcat to automate cracking processes.
### Options can be combined to tailor cracking jobs to perform more, or less, 
### work for various hash algorithms.
### 
### The script also includes options to output cracked hashes, with and 
### without usernames, as well as unique and non-unique lists of just the
### passwords for use in password spraying and tools like pipal, respectively.
###
###     v1.0.0  Timothy McKenzie  01-01-2018
###     v1.0.1  Timothy McKenzie  01-18-2018
###     v1.0.2  Timothy McKenzie  04-16-2018
###############################################################################

import sys
import os
import re
import argparse
import select
import termios
import tty
import pty
import collections
import copy
from time import sleep
from subprocess import Popen, check_output
from threading  import Thread
from queue import Queue, Empty

VERBOSITY=0
### Path Variables
# Path in which the wordlists, rules, and masks directories reside; usually the same folder in which the hashcat executable resides.
# Be sure to include the "/" at the end of the path.
BASESUPPORTFILESPATH = '~/autocrack/'
# Path in which the hashcat executable sits; may be the same path as set for BASESUPPORTFILESPATH
# Be sure to incldue the "/" at the end of the path.
BASEEXEPATH = '/usr/local/hashcat/'
# Name of the hashcat executable
BASECOMMAND = 'hashcat'
# Full path to the john executble
JTRPATH = '/usr/local/JohnTheRipper/run/john'

### Categories of Rules (each of these rules must be present in the 
### BASESUPPORTFILESPATH\rules directory, if a rule file is missing it will be skipped)
# The list of rules that are run with the "-r combos", or "-r all", options 
COMBORULES = [['leetspeakv2.rule','leetspeakv2.rule'],['toggles3.rule','leetspeakv2.rule'],['prepend_ldus.rule','append_ldus.rule'],['dive.rule','leetspeakv2.rule']]
# The list of rules that are run with the "-r singles", or "-r all", options
ALLSINGLERULES = ['nsa64.rule','leetspeakv2.rule','hob064.rule','combinator.rule','best64.rule','specific.rule','T0XlC-insert_space_and_special_0_F.rule','InsidePro-PasswordsPro.rule','T0XlC-insert_top_100_passwords_1_G.rule','Ninja-leetspeak.rule','T0XlC.rule','InsidePro-HashManager.rule','T0XlC-insert_00-99_1950-2050_toprules_0_F.rule','generated.rule','T0XlCv1.rule','d3ad0ne.rule','Incisive-leetspeak.rule','OneRuleToRuleThemAll.rule','generated2.rule','d3adhob0.rule','epixoip_combined.rule','dive.rule','_NSAKEY.v1.dive.rule','_NSAKEY.v2.dive.rule']
# The list of rules that are run with the "-r simple" option
SIMPLERULES = ['nsa64.rule','leetspeakv2.rule','hob064.rule','combinator.rule','best64.rule','specific.rule','T0XlC-insert_space_and_special_0_F.rule','InsidePro-PasswordsPro.rule','T0XlC-insert_top_100_passwords_1_G.rule','Ninja-leetspeak.rule']

def output(intLevel, strMessage):
    # intLevel is the severity level of the message being passed to the output function
    global VERBOSITY
    if intLevel == 0:
        print('{}'.format(strMessage))
    elif intLevel == 1 and VERBOSITY >= 1:
        print('\nVERBOSE MESSAGE: {}\n'.format(strMessage))
    elif intLevel == VERBOSITY == 2:
        print('{}'.format(strMessage), end='')

def checkDone(strOutput):
    doneStatus = False
    doneStatements = ['All hashes found in potfile!', 'No hashes loaded']
    doneReMatch = re.findall(r'Recovered.*?\(([0-9]{3}\.00%)', strOutput)
    if len(doneReMatch) > 0:
        if doneReMatch[-1] == '100.00%':
            doneStatus = True
    if any(searchStr in strOutput for searchStr in doneStatements):
        doneStatus = True
    if re.search(r'Status.*?Quit', strOutput) != None:
        doneStatus = True
    return doneStatus

def checkWhatsCracked(hashcatFlags):
    hashcatCMD = [BASEEXEPATH + BASECOMMAND]
    hashcatCMD += hashcatFlags
    strCracked = check_output(' '.join(hashcatCMD), shell=True)
    if strCracked:
        output(0, 'Hashes Cracked:\n'+strCracked.decode()) 


def callHashcat(hashcatFlags, logfile, currentStatus):
    exitStatus = currentStatus
    if hashcatFlags != []:
        hashcatCMD = [BASEEXEPATH + BASECOMMAND]
        hashcatCMD += hashcatFlags
        sessionLog = ''
        # save original tty setting then set it to raw mode
        old_tty = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())
        # open pseudo-terminal to interact with subprocess
        master_fd, slave_fd = pty.openpty()
        # use os.setsid() make it run in a new process group, or bash job control will not be enabled
        p = Popen(' '.join(hashcatCMD),
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            universal_newlines=True,
            shell=True)
        while p.poll() is None:
            r, w, e = select.select([sys.stdin, master_fd], [], [], 0)
            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 10240)
                os.write(master_fd, d)
            elif master_fd in r:
                o = os.read(master_fd, 10240)
                if o:
                    output(2, o.decode())
                    #os.write(sys.stdout.fileno(), o)
                    sessionLog += o.decode()
        if logfile:
            f = open(logfile, 'a')
            f.write(sessionLog)
            f.close()
        # Check to see if cracking completed, to prevent hashcat from being called again
        if checkDone(sessionLog):
            exitStatus = 'Done'
        # restore tty settings back
        output(1, '\r\nReturn Code: '+str(p.returncode)+'\r\n<DONE>\r\n')
        os.close(master_fd)
        os.close(slave_fd)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
    return exitStatus


def buildCommand(passedArgs):
    hashcatArgs = []
    if passedArgs.listhashmode != None:
        hashcatArgs = [['--help'], 'Done']
        if passedArgs.listhashmode == True:
            hashcatArgs[0].extend(['|', 'sed', "'1,/Hash modes/d'"])
        elif passedArgs.listhashmode != "":
            hashcatArgs[0].extend(['|', 'sed', "'1,/Hash modes/d'", '|', 'grep', '-i', passedArgs.listhashmode])
    elif passedArgs.show:
        if passedArgs.hashmode != None and passedArgs.inputfile != None:
            hashcatArgs = [['-m', passedArgs.hashmode, passedArgs.inputfile], 'Done']
            hashcatArgs[0].append('--show')
            if passedArgs.username:
                hashcatArgs[0].append('--username')
        else:
            hashcatArgs = [['GetHelp'], 'Done']
    elif passedArgs.pwds or passedArgs.pwdsunique:
        if passedArgs.hashmode != None and passedArgs.inputfile != None:
            hashcatArgs = [['-m', passedArgs.hashmode, passedArgs.inputfile], 'Done']
            if passedArgs.pwdsunique:
                hashcatArgs[0].extend(['--show', '|', 'tail', '-n', '+4', '|', 'awk', '-F', "':'", "' { print $NF } '"])
            else:
                hashcatArgs[0].extend(['--show', '--username', '|', 'tail', '-n', '+4', '|', 'awk', '-F', "':'", "' { print $NF } '"])
        else:
            hashcatArgs = [['GetHelp'], 'Done']
    elif passedArgs.hashmode != None and passedArgs.inputfile != None:
        hashcatArgs = [['-w', '3', '-m', passedArgs.hashmode, passedArgs.inputfile], '']
        if passedArgs.force:
            hashcatArgs[0].insert(0, '--force')
        if passedArgs.brute != None and (passedArgs.brute <= 55 and passedArgs.brute >=1):
            hashcatArgs[1] = 'Brute'
            if re.search(r'[b-ce-km-rtv-z]', passedArgs.brutemask) == None:
                for newArg in ['--increment-max='+str(passedArgs.brute), '--increment-min=1', '-i', '3', '-a']:
                    hashcatArgs[0].insert(0, newArg)
                if len(passedArgs.brutemask) == 2 and re.search(r'\?[adlsu]', passedArgs.brutemask) != None:
                    hashcatArgs[0].append(passedArgs.brutemask*passedArgs.brute)
                    output(0, 'Cracking with {} character set through brute force.'.format(passedArgs.brutemask*passedArgs.brute))
                else:
                    if len(passedArgs.brutemask)/2 == passedArgs.brute:
                        maskPos = 0
                        tempMask = ''
                        while maskPos <= (len(passedArgs.brutemask) - 1):
                            if re.search(r'\?[adlsu]', passedArgs.brutemask[maskPos:maskPos+2]) != None:
                                tempMask += passedArgs.brutemask[maskPos:maskPos+2]
                                maskPos += 2
                            else:
                                break
                        if tempMask == passedArgs.brutemask:
                            hashcatArgs[0].append(passedArgs.brutemask)
                            output(0, 'Cracking with {} character set through brute force.'.format(passedArgs.brutemask))
                        else:
                            output(0, 'Invalid mask.  Exiting...\r\n')
                            hashcatArgs = [['GetHelp'], 'Done']
                    else:
                        output(0, 'Invalid mask.  Exiting...\r\n')
                        hashcatArgs = [['GetHelp'], 'Done']
            else:
                output(0, 'Invalid mask.  Exiting...\r\n')
                hashcatArgs = [['GetHelp'], 'Done']
        elif passedArgs.wordlists != None and passedArgs.wordlists[0] != []:
            hashcatArgs[1] = 'Wordlist'
            hashcatArgs[0].append(passedArgs.wordlists[0][0])
            strCrackStatus = 'Cracking with {} wordlist'.format(passedArgs.wordlists[0][0])
            if passedArgs.wordlists[1] == 'Done':
                if passedArgs.rules != None and passedArgs.rules != []:
                    if isinstance(passedArgs.rules[0], collections.Sequence) and not isinstance(passedArgs.rules[0], str):
                        for eachRule in passedArgs.rules[0]:
                            hashcatArgs[0].append('-r')
                            hashcatArgs[0].append(BASESUPPORTFILESPATH+'rules/'+eachRule)
                            strCrackStatus += ' and {} rule'.format(eachRule)
                    else:
                        hashcatArgs[0].append('-r')                      
                        hashcatArgs[0].append(BASESUPPORTFILESPATH+'rules/'+passedArgs.rules[0])
                        strCrackStatus += ' and {} rule'.format(passedArgs.rules[0])
                else:
                    hashcatArgs = [[None], 'Done']
            output(0, strCrackStatus)
        else:
            hashcatArgs = [[None], 'Done']
    else:
        hashcatArgs = [['GetHelp'], 'Done']
    return hashcatArgs


def customArgToList(argString):
    if ', ' in argString:
        argList = argString.split(', ')
    elif ',' in argString:
        argList = argString.split(',')
    else:
        argList = [argString]
    return argList

def getFileSize(path):
    with open(path, 'rb') as f:
        lines = 0
        bufferSize = 1024 * 1024
        readFile = f.raw.read
        buf = readFile(bufferSize)
        while buf:
            lines += buf.count(b'\n')
            buf = readFile(bufferSize)
    return lines


def findWordlists(intMaxLines,wlfilter):
    wordList = []
    tempList = []
    if wlfilter != None and wlfilter != '':
        wlfilter = customArgToList(wlfilter)
    else:
        wlfilter = []
    if wlfilter == []:
        tempList = [os.path.join(BASESUPPORTFILESPATH,'wordlists/',wlf) for wlf in os.listdir(path=os.path.join(BASESUPPORTFILESPATH,'wordlists/'))]
    elif wlfilter != []:
        # Build a filtered list of all the files in the BASESUPPORTFILESPATH
        for eachFilter in wlfilter:
            tempList.extend((os.path.join(wlBasePath, wlf) for wlBasePath, wlDirs, wlFiles in os.walk(os.path.join(BASESUPPORTFILESPATH,'wordlists/')) for wlf in wlFiles if re.match(r'.*?'+eachFilter+'.*', wlf)))
    if intMaxLines > 0:
        if tempList != []:
            # Retrieve a unique set of files
            tempList = list(set(tempList))
            # Sort the list by size, to be able to end the search for files over the max # of lines can end without going through all the files.
            sortedList = sorted(tempList, key = os.path.getsize)
            overMaxLinesCtr = 0
            for wlfile in sortedList:
                if getFileSize(wlfile) <= intMaxLines:
                    wordList.append(wlfile)
                    overMaxLinesCtr = 0
                else:
                    overMaxLinesCtr += 1
                # if two wordlists in a row have a length greater than the specified max, exit the loop
                if overMaxLinesCtr >= 2:
                    exit
    else:
        if tempList != []:
            wordList = sorted(tempList, key = os.path.getsize)
    return wordList
    

def main():
    # Setup some variables
    global VERBOSITY
    exitCode = 'Continue'
    masterRules = []
    masterWordlist = [[], 'Continue']
    # Collect and verify the commandline arguments
    argParser=argparse.ArgumentParser()
    argParser.add_argument('-b', '--brute', type=int, choices=range(1,56), metavar='NUM', help='Incremental mask-based brute force. Specify max length (1-55)')
    argParser.add_argument('-bm', '--brutemask', default='?a', 
        help='Character types to brute force (?a, ?u, ?l, ?s, ?d); If only one type is specified, all positions will be brute forced with that character type; Else, one type must be specified for each position (i.e. -b 3 -bm ?u?d?s)')
    argParser.add_argument('-cr', '--customrules', help='Comma separated list of rules to run; rules are run in the order of left to right')
    argParser.add_argument('-cw', '--customwl', help='Comma separated list of the full path to one or more wordlists')
    argParser.add_argument('-f', '--force', action='store_true', help='Pass the force parameter to Hashcat')
    argParser.add_argument('-i', '--inputfile', help='Path to file with hashes')
    argParser.add_argument('-l', '--logfile', help='Path to log the cracking session')
    argParser.add_argument('-lh', '--listhashmode', const=True, nargs='?', help='List hash types and their associated mode; provide a keyword to filter results')
    argParser.add_argument('-lw', '--listwordlists', choices=['all','small','custom'], 
        help='List wordlists in BASESUPPORTFILESPATH/wordlists; -t (filter) and -ws (wordlist size) can be used to affect results')
    argParser.add_argument('-m', '--hashmode', help='Hashcat cracking algorithm')
    argParser.add_argument('-p', '--pwds', action='store_true', help='Output the list of cracked passwords (for pipal analysis)')
    argParser.add_argument('-pu', '--pwdsunique', action='store_true', help='Output a uniqued list of cracked passwords')
    argParser.add_argument('-r', '--rules', choices=['all','simple','singles','combos'], help='Specify which hashcat set of rules to use')
    argParser.add_argument('-s', '--show', action='store_true', help='Display cracked credentials')
    argParser.add_argument('-t', '--wlfilter', help='Filters the wordlists to only include file names that contain the keyword')
    argParser.add_argument('-u', '--username', action='store_true', help='Pass the username parameter to Hashcat')
    argParser.add_argument('-v', '--verbose', type=int, help='Specify a verbosity level: 0: Informational, 1: Verbose, 2: Include Hashcat Output', choices=range(0,3), default=0)
    argParser.add_argument('-w', '--wordlists', choices=['all','small','custom'], 
        help='Specify which set of wordlists to use; "custom" uses the -ws option to specify the maximum file size')
    argParser.add_argument('-ws', '--wordlistsize', type=int, default=500000, help='Filter wordlists to files of a maximum number of lines; Default = 500,000; 0 = all wordlists')
    args = argParser.parse_args()
    output(1, "Arguments passed to Autocrack"+str(args))
    VERBOSITY = args.verbose
    # Handle the wordlist argument
    if args.wordlists or args.listwordlists:
        if args.wordlists == 'custom' or args.listwordlists == 'custom':
            if args.wordlistsize == 0:
                output(0, 'Finding all wordlists in path %s...' % (BASESUPPORTFILESPATH+'wordlists/'))
                masterWordlist[0] = findWordlists(0,args.wlfilter)
            elif args.wordlistsize > 0:
                output(0, 'This may take a few minutes.  Finding wordlists with %d or fewer lines in path %s...' % (args.wordlistsize,BASESUPPORTFILESPATH+'wordlists/'))
                masterWordlist[0] = findWordlists(args.wordlistsize,args.wlfilter)
            else:
                output(0, 'Invalid wordlist size.  Skipping wordlists.')
                args.wordlists = None
        elif args.wordlists == 'small' or args.listwordlists == 'small':
            output(0, 'Finding wordlists with %d or fewer lines in path %s...' % (500000,BASESUPPORTFILESPATH+'wordlists/'))
            masterWordlist[0] = findWordlists(500000,args.wlfilter)
        elif args.wordlists == 'all' or args.listwordlists == 'all':
            output(0, 'Finding all wordlists in path %s...' % (BASESUPPORTFILESPATH+'wordlists/'))
            masterWordlist[0] = findWordlists(0,args.wlfilter)
        if masterWordlist[0]:
            output(0, 'The following wordlists matched the specified criteria:')
            for eachPath in masterWordlist[0]:
                output(0, '%s' % eachPath)
            if args.wordlists == None and args.listwordlists:
                exitCode = 'Done'
        else:
            output(0, 'No wordlists matched the specified criteria.  No wordlist or rules attacks will be run.')
            args.wordlists = None
    # Handle the rules argument
    if args.rules:
        if args.rules == 'all':
            masterRules.extend(ALLSINGLERULES)
            masterRules.extend(COMBORULES)
        elif args.rules == 'simple':
            masterRules.extend(SIMPLERULES)
        elif args.rules == 'singles':
            masterRules.extend(ALLSINGLERULES)
        elif args.rules == 'combos':
            masterRules.extend(COMBORULES)
    # Convert to List and handle custom rules
    if args.customrules:
        args.customrules = customArgToList(args.customrules)
        masterRules.extend(args.customrules)
    # Convert to List and handle custom wordlists
    if args.customwl:
        args.customwl = customArgToList(args.customwl)
        masterWordlist[0] = args.customwl + masterWordlist[0]
    args.rules = list(masterRules)
    output(1, 'Rules to be applied to each wordlist\n'+str(args.rules))
    args.wordlists = [eachWL[:] for eachWL in masterWordlist]
    # Loop through all the work specified
    while exitCode != 'Done':
        hashcatFlags, exitCode = buildCommand(args)
        if hashcatFlags and hashcatFlags[0] == 'GetHelp':
            argParser.print_help()
            break
        if exitCode == 'Brute':
            args.brute = None
        elif exitCode == 'Wordlist':
            if args.wordlists[1] == 'Continue':
                args.wordlists[0].pop(0)
                if args.wordlists[0] == []:
                    args.wordlists = [eachWL[:] for eachWL in masterWordlist]
                    args.wordlists[1] = 'Done'
            elif args.wordlists[1] == 'Done':
                if args.rules:
                    args.rules.pop(0)
                    if args.rules == []:
                        args.wordlists[0].pop(0)
                        if args.wordlists[0]:
                            args.rules = list(masterRules)
        output(1, "Flags passed to this iteration of Hashcat"+str(hashcatFlags))
        if hashcatFlags != [None]:
            exitCode = callHashcat(hashcatFlags, args.logfile, exitCode)
            wcArgs = copy.deepcopy(args)
            wcArgs.show = True
            wchcFlags, wcExitCode = buildCommand(wcArgs) 
            checkWhatsCracked(wchcFlags)
        else:
            output(0, 'Nothing else to do.  Exiting...')


if __name__=='__main__':
    main()
