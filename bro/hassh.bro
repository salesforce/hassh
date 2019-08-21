#                               HASSH                                #
#             SSH Key Initiation Exchange Fingerprinting             #
#                                                                    #
# Script Version: v1.5 22 August 2019                                #
# Authors: Ben Reardon (breardon@salesforce.com, @benreardon)        #
#        : Jeff Atkinson (jatkinson@salesforce.com)                  #
#        : John Althouse (jalthouse@salesforce.com)                  #
# Description:  This bro script appends hassh data to ssh.log        #
#               by enumerating the SSH_MSG_KEXINIT packets sent      #
#               as clear text between the client and server as part  # 
#               of the negotiation of an SSH connection.             #
#                                                                    #
# Copyright (c) 2018, salesforce.com, inc.                           #
# All rights reserved.                                               #
# SPDX-License-Identifier: BSD-3-Clause                              #
# For full license text, see the LICENSE file in the repo root or    #
# https://opensource.org/licenses/BSD-3-Clause                       #


module SSH;

export {
    type HASSHStorage: record {
        hasshVersion:string &log &default="1.1"; # ANY change in hassh/hasshServer composition requires Version update 
        hassh:   string   &log &optional &default="";
        hasshServer:   string  &log &optional &default="";
        
        # Client variables #
        ckex:    string   &log &optional &default="";
        cshka:   string   &log &optional &default="";
        ceacts:  string   &log &optional &default="";
        cmacts:  string   &log &optional &default="";
        ccacts:  string   &log &optional &default="";
        #clcts:  string   &log &optional &default=""; 
        hasshAlgorithms:  string  &log &optional &default="";
        
        # Server variables #
        skex:     string  &log &optional &default="";
        sshka:    string  &log &optional &default="";
        seastc:   string  &log &optional &default="";
        smastc:   string  &log &optional &default="";
        scastc:   string  &log &optional &default="";
        #slstc:   string  &log &optional &default="";
        hasshServerAlgorithms:  string  &log &optional &default="";
    };
}

redef record connection += {
    hassh: HASSHStorage &optional;
};
    
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


# Build Client Application fingerprint #
function get_hassh(c:connection, capabilities: SSH::Capabilities ) {
    c$hassh = HASSHStorage();
    c$hassh$ckex   = join_string_vec(capabilities$kex_algorithms,",");
    c$hassh$ceacts = join_string_vec(capabilities$encryption_algorithms$client_to_server,",");
    c$hassh$cmacts = join_string_vec(capabilities$mac_algorithms$client_to_server,",");
    c$hassh$ccacts = join_string_vec(capabilities$compression_algorithms$client_to_server,",");
    c$hassh$cshka  = join_string_vec(capabilities$server_host_key_algorithms,","); # The Host key algorithm set may be useful information by itself but is not included in the hassh.
    #c$hassh$clcts  = join_string_vec(capabilities$languages$client_to_server,","); # The Languages field may be useful information by itself but is not included in the hasshServer.
    c$hassh$hasshAlgorithms = string_cat(c$hassh$ckex,";",c$hassh$ceacts,";",c$hassh$cmacts,";",c$hassh$ccacts); # Contatenate the four selected lists of algorithms (Key,Enc,MAC,Compression) to build the Client hash
    c$hassh$hassh = md5_hash(c$hassh$hasshAlgorithms);
}

# Build Server Application fingerprint #
function get_hasshServer(c:connection, capabilities: SSH::Capabilities ) {
    c$hassh = HASSHStorage();
    c$hassh$skex   = join_string_vec(capabilities$kex_algorithms,",");
    c$hassh$seastc = join_string_vec(capabilities$encryption_algorithms$server_to_client,",");
    c$hassh$smastc = join_string_vec(capabilities$mac_algorithms$server_to_client,",");
    c$hassh$scastc = join_string_vec(capabilities$compression_algorithms$server_to_client,",");
    c$hassh$sshka  = join_string_vec(capabilities$server_host_key_algorithms,","); # The Host key algorithm set may be useful information by itself but is not included in the hasshServer.
    #c$hassh$slstc  = join_string_vec(capabilities$languages$server_to_client,","); # The Languages field may be useful information by itself but is not included in the hasshServer.
    c$hassh$hasshServerAlgorithms = string_cat(c$hassh$skex,";",c$hassh$seastc,";",c$hassh$smastc,";",c$hassh$scastc); # Contatenate the four selected lists of algorithms (Key,Enc,Message,Compression) to build the Server hash
    c$hassh$hasshServer = md5_hash(c$hassh$hasshServerAlgorithms);
}

# Event #
event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities) {
    if ( !c?$ssh ) {return;}
    c$hassh = HASSHStorage();
    
    # Prior to 2.6.0 bro has a bug which it reverses the Client/server flag.
    # See https://github.com/zeek/zeek/pull/191
    # The "if" statements here do a version check to account for this bug in versions older than 2.6.0
    
    if ((Version::info$version_number < 20600 && capabilities$is_server == T) || (Version::info$version_number >= 20600 && capabilities$is_server == F) ) {
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
    if ( (Version::info$version_number < 20600 && capabilities$is_server == F) || (Version::info$version_number >= 20600 && capabilities$is_server == T) ) {
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
}
