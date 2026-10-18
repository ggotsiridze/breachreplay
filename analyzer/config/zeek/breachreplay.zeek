##! BreachReplay Zeek policy.
##!
##! Loaded in addition to Zeek's default base scripts when analyzing a capture.
##! It raises notices for behaviour BreachReplay's correlation engine cares
##! about. It never acts on traffic; Zeek runs offline against a file.

@load base/frameworks/notice
@load base/protocols/smb
@load base/protocols/ntlm

module BreachReplay;

export {
    redef enum Notice::Type += {
        ## An SMB tree connect to an administrative share (ADMIN$ or C$).
        Admin_Share_Access,
        ## One host opened connections to the same TCP port on many internal hosts.
        Internal_Port_Sweep,
    };

    ## Distinct internal destinations on the same port before a sweep notice.
    const sweep_threshold = 3 &redef;
}

# Use the analyst's private address space as local networks.
redef Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    if ( /[Aa][Dd][Mm][Ii][Nn]\$|[Cc]\$/ in path )
        NOTICE([$note=Admin_Share_Access,
                $msg=fmt("SMB tree connect to administrative share %s", path),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, path)]);
    }

global sweep_targets: table[addr, port] of set[addr] &create_expire=60sec;

function track_probe(c: connection)
    {
    local o = c$id$orig_h;
    local r = c$id$resp_h;
    local p = c$id$resp_p;
    if ( ! Site::is_local_addr(o) || ! Site::is_local_addr(r) )
        return;
    if ( [o, p] !in sweep_targets )
        sweep_targets[o, p] = set();
    add sweep_targets[o, p][r];
    if ( |sweep_targets[o, p]| == sweep_threshold )
        NOTICE([$note=Internal_Port_Sweep,
                $msg=fmt("%s probed %d internal hosts on %s", o, sweep_threshold, p),
                $src=o, $p=p,
                $identifier=cat(o, p)]);
    }

event connection_attempt(c: connection)
    {
    track_probe(c);
    }

event connection_rejected(c: connection)
    {
    track_probe(c);
    }
