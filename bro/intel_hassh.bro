# This Bro script adds HASSH to the Bro Intel Framework as Intel::HASSH
#
# Author: Josh Guild

module Intel;

export {
    redef enum Intel::Type += { Intel::HASSH };
}

export {
    redef enum Intel::Where += { SSH::IN_HASSH };
}

event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities)
        {
        if ( c$ssh?$hassh )
        Intel::seen([$indicator=c$ssh$hassh, $indicator_type=Intel::HASSH, $conn=c, $where=SSH::IN_HASSH]);
        }
