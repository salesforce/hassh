# hassh.bro
[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Features
**hassh.bro** by default will add these fields to your bro ssh.log file 
- hasshVersion
- hassh, hasshAlgorithms 
- hasshServer, hasshServerAlgorithms
- cshka (Client Host Key Algorithms), sshka (Server Host Key Algorithms)  
- The script has been tested on Bro 2.4.1, 2.5, 2.5.1 and 2.5.5. 
- Note that bro currently ( <= v2.5.5) has a bug which reverses the Client/server flag, however the logic in this script reverses and in effect corrects this bug. Therefore once the bro bug is patched, the logic in this script also needs return to the proper form. Failure to update bro and not the script will result in the Server and Client packets being processed incorrectly, in effect swapping around hassh with hassServer.  

## Installation
Place hassh.bro in bro/share/bro/site/hassh and add this line to your local.bro script:
```bash
@load ./hassh
```
If running Bro >=2.5 or a Bro product like Corelight, install by using the Bro Package Manager with this command:
```bash 
bro-pkg install hassh
```


## Configuration
**hassh.bro** by default will add these fields to your bro ssh.log file: ```hasshVersion, hassh, hasshAlgorithms, hasshServer and hasshServerAlgorithms, cshka, sshka.``` If you don't want some of these fields to be logged, simply comment those field lines out in each of the locations within hassh.bro as shown in the code blocks below.
```bash
redef record SSH::Info += {
    hasshVersion:  string  &log &optional;
    hassh:         string  &log &optional;
    hasshServer:   string  &log &optional;
    
    # ===> Log Client variables <=== #
    # Comment out any fields that are not required to be logged in their raw form to ssh.log
    #ckex:    string   &log &optional;
    cshka:   string   &log &optional; 
    #ceacts:  string   &log &optional; 
    #cmacts:  string   &log &optional;
    #ccacts:  string   &log &optional; 
    #clcts:   string   &log &optional;
    hasshAlgorithms:  string  &log &optional;
    
    # ===> Log Server variables <=== #
    # Comment out any fields that are not required to be logged in their raw form to ssh.log
    #skex:     string  &log &optional; 
    sshka:    string  &log &optional; 
    #seastc:   string  &log &optional; 
    #smastc:   string  &log &optional; 
    #scastc:   string  &log &optional; 
    #slstc:    string  &log &optional;
    hasshServerAlgorithms:  string  &log &optional;
};
```
```bash
    if ( capabilities$is_server == T ) {
        get_hassh(c, capabilities);
        c$ssh$hasshVersion = c$hassh$hasshVersion;
        c$ssh$hassh  = c$hassh$hassh;
        
        # ===> Log Client variables <=== #
        # Comment out any fields that are not required to be logged in their raw form to ssh.log
        #c$ssh$ckex   = c$hassh$ckex;
        c$ssh$cshka  = c$hassh$cshka;
        #c$ssh$ceacts = c$hassh$ceacts;
        #c$ssh$cmacts = c$hassh$cmacts;
        #c$ssh$ccacts = c$hassh$ccacts;
        #c$ssh$clcts  = c$hassh$clcts;
        c$ssh$hasshAlgorithms = c$hassh$hasshAlgorithms;
    }
    if ( capabilities$is_server == F ) {
        get_hasshServer(c, capabilities);
        c$ssh$hasshVersion = c$hassh$hasshVersion;
        c$ssh$hasshServer = c$hassh$hasshServer;
        
        # ===> Log Server variables <=== #
        # Comment out any fields that are not required to be logged in their raw form to ssh.log
        #c$ssh$skex   = c$hassh$skex;
        c$ssh$sshka  = c$hassh$sshka;
        #c$ssh$seastc = c$hassh$seastc;
        #c$ssh$smastc = c$hassh$smastc;
        #c$ssh$scastc = c$hassh$scastc;
        #c$ssh$slstc  = c$hassh$clcts;
        c$ssh$hasshServerAlgorithms = c$hassh$hasshServerAlgorithms;
    }
```

After ammending the bro script, don't forget to reload bro. 
```bash
broctl stop
broctl install
broctl start
```

## Credits:
HASSH was conceived and developed by [Ben Reardon](mailto:breardon@salesforce.com) (@benreardon) within the Detection Cloud Team at Salesforce, with inspiration and contributions from [Adel Karimi](mailto:akarimishiraz@salesforce.com) (@0x4d31) and the [JA3 crew](https://github.com/salesforce/ja3/)  crew:[John B. Althouse](mailto:jalthouse@salesforce.com)  , [Jeff Atkinson](mailto:jatkinson@salesforce.com) and [Josh Atkins](mailto:j.atkins@salesforce.com)
