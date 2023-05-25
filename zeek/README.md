# hassh.zeek
[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Features
**hassh.zeek** by default will add these fields to your Zeek ssh.log file 
- hasshVersion
- hassh, hasshAlgorithms 
- hasshServer, hasshServerAlgorithms
- cshka (Client Host Key Algorithms), sshka (Server Host Key Algorithms)  
- The script has been tested on Bro 2.5, 2.5.1, 2.5.5, 2.6.0, 2.6.1, 2.6.3, 3.0.0 and 3.1.2
- Note that Zeek (formerly bro) versions < v2.6.0 had a bug which reversed the Client/server flag , see https://github.com/zeek/zeek/pull/191. The current version of the hassh.zeek script does version checking to deal with these version issues. Failure to update Zeek and not the hassh.zeek script will result in the Server and Client packets being processed incorrectly, in effect swapping around hassh with hasshServer.  

## Installation
Place hassh.zeek in zeek/share/zeek/site/hassh and add this line to your local.zeek script:
```bash
@load ./hassh
```
If running Zeek >= 3.0.0 or a Zeek product like Corelight, install by using the Zeek Package Manager with this command:
```bash 
zkg install hassh
```


## Configuration
**hassh.zeek** by default will add these fields to your Zeek ssh.log file: ```hasshVersion, hassh, hasshAlgorithms, hasshServer and hasshServerAlgorithms, cshka, sshka.``` If you don't want some of these fields to be logged, simply comment those field lines out in each of the locations within hassh.zeek as shown in the code blocks below.
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

After ammending the Zeek script, don't forget to reload Zeek. 
```bash
zeekctl stop
zeekctl install
zeekctl start
```

## Credits:
HASSH was conceived and developed by [Ben Reardon](mailto:breardon@salesforce.com) (@benreardon) within the Detection Cloud Team at Salesforce, with inspiration and contributions from [Adel Karimi](mailto:akarimishiraz@salesforce.com) (@0x4d31) and the [JA3 crew](https://github.com/salesforce/ja3/)  crew:[John B. Althouse](mailto:jalthouse@salesforce.com)  , [Jeff Atkinson](mailto:jatkinson@salesforce.com) and [Josh Atkins](mailto:j.atkins@salesforce.com)
