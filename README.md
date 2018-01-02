# autocrack
This python script is a Hashcat (https://hashcat.net) wrapper to help automate the cracking process.  The script includes multiple functions to select a set of wordlists and rules, as well as the ability to run a bruteforce attack, with custom masks, before the wordlist/rule attacks.

```usage: autocrack.py [-h] [-b {1,2,3,4,5,6,7,8}] [-bm BRUTEMASK]
                    [-cr CUSTOMRULES] [-cw CUSTOMWL] [-f] [-i INPUTFILE]
                    [-l LOGFILE] [-lh [LISTHASHMODE]] [-lw {all,small,custom}]
                    [-m HASHMODE] [-p] [-pu] [-r {all,simple,singles,combos}]
                    [-s] [-t WLFILTER] [-u] [-w {all,small,custom}]
                    [-ws WORDLISTSIZE]

optional arguments:
  -h, --help            show this help message and exit
  -b {1,2,3,4,5,6,7,8}, --brute {1,2,3,4,5,6,7,8}
                        Start cracking with brute force. Specify max length (1-8)
  -bm BRUTEMASK, --brutemask BRUTEMASK
                        Character types to brute force (?a, ?u, ?l, ?s, ?d);
                        If only one type is specified, all positions will be
                        brute forced with that character type
  -cr CUSTOMRULES, --customrules CUSTOMRULES
                        Comma separated list of rules to run; rules are run in
                        the order of left to right
  -cw CUSTOMWL, --customwl CUSTOMWL
                        Comma separated list of the full path to one or more wordlists
  -f, --force           Pass the force parameter to Hashcat
  -i INPUTFILE, --inputfile INPUTFILE
                        Path to file with hashes
  -l LOGFILE, --logfile LOGFILE
                        Path to log the cracking session
  -lh [LISTHASHMODE], --listhashmode [LISTHASHMODE]
                        List hash types and their associated mode; provide a
                        keyword to filter results
  -lw {all,small,custom}, --listwordlists {all,small,custom}
                        List wordlists in BASESUPPORTFILESPATH/wordlists; -t
                        (filter) and -ws (wordlist size) can be used to affect
                        results
  -m HASHMODE, --hashmode HASHMODE
                        Hashcat cracking algorithm
  -p, --pwds            Output the list of cracked passwords (for pipal
                        analysis)
  -pu, --pwdsunique     Output a uniqued list of cracked passwords
  -r {all,simple,singles,combos}, --rules {all,simple,singles,combos}
                        Specify which hashcat set of rules to use
  -s, --show            Display cracked credentials
  -t WLFILTER, --wlfilter WLFILTER
                        Filters the wordlists to only include file names that
                        contain the keyword
  -u, --username        Pass the username parameter to Hashcat
  -w {all,small,custom}, --wordlists {all,small,custom}
                        Specify which set of wordlists to use; "custom" uses
                        the -ws option to specify the maximum file size
  -ws WORDLISTSIZE, --wordlistsize WORDLISTSIZE
                        Filter wordlists to files of a maximum number of
                        lines; Default = 500,000; 0 = all wordlists```

To Do:
 - Add function to one-step AD domain hash dumps (lm -> nt)
 - Include mask attacks
 - Track which wordlists / rules / masks crack a password
