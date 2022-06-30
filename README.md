# TI-MFA-linux
![build](https://github.com/sebasnabas/TI-MFA-linux/actions/workflows/build.yml/badge.svg)
![test](https://github.com/sebasnabas/TI-MFA-linux/actions/workflows/test.yml/badge.svg)

**Note:** TI-MFA is currently only implemented for MPLS. Srv6 is not supported (yet).

A Linux kernel module for the Topology Independent Multi Failure Alternate (TI-MFA) algorithm from [^1] ('described from the viewpoint of the node v where the packet hits another failed link'):
>   1) Flush the label stack except for the destination t.
>   2) Based on all link failures stored in the packet header,
>       determine the shortest path P to the destination t in the
>       remaining network G′.
>   3) Add segments to the label stack of the packet as follows:
>
>       • Index the nodes on P as v = v1, v2, …, vx = t.
>           Compute the node vi on P with the highest index s.t. the shortest path from v is identical in G′ (with failures) and G (without failures) and set it as the top of the label stack.
>           If this node is v, push the link (v1, v2 = vi) as the top of the label stack.
>           For the second item on the label stack, start over with vi as the starting node, etc., until vi = t.

## Implementation

### Architecture
Needs Kernel `>= 4.2` (For Ingress Hook)

#### Control plane tool
`ti-mfa-conf` configuration tool for modifying backup routes in case of a link failure:
* adding a route      `ti-mfa-conf add MAC-MAC MPLSLABEL DEV [ NETNS_PID ]`
* deleting a route    `ti-mfa-conf del MAC-MAC MPLSLABEL DEV [ NETNS_PID ]`
* deleting all routes `ti-mfa-conf flush`
* showing all routes  `ti-mfa-conf show`

where
* `MAC` is an Ethernet mac address,
* `MPLSLABEL` is an MPLS label,
* `DEV` is the name of a network interface the packet should be sent out on,
* `NETNS_PID` is optional and the process identifier for whose network namespace the route should be saved.


#### Kernel Module (Data plane)
```mermaid
graph TB
    subgraph Kernel Module
        IP((Incoming Packet)) --> IH_IF{"if (MPLS)"}

        2_TI_MFA -.-> ROUTE_READ

        subgraph NF_IH["Netfilter Ingress Hook"]
            IH_IF      -->|true| 1_1_TI_MFA(1. Flush MPLS headers)
            1_1_TI_MFA --> IF_TI_MFA{"if (last MPLS label == 15)"}
            IF_TI_MFA  -->|true| 1_2_TI_MFA(Flush TI_MFA_Headers)
            1_2_TI_MFA --> SLF(Set local link failures)
            IF_TI_MFA  -->|false| SLF
            SLF        --> 2_TI_MFA(2. Get shortest path)
            2_TI_MFA   -->       IF_LF_PHP{"if (No Link Failures && no Nexthop Labels)"}
            IF_LF_PHP  -->|false| 3_TI_MFA(3. Set label stack)
            IF_LF_PHP  -->|true| PHP(PHP: Set package type to IP)
        end

        IH_IF    -->|false| KR((Kernel Routing))
        SLF      -.-> NEIGH_READ
        3_TI_MFA -->  XMIT(Send Packet)
        PHP      -->  XMIT
        XMIT     --> OP((Outgoing Packet))

        subgraph Netdev Notifier
            NETDEV_GOING_DOWN>NETDEV_GOING_DOWN] --> NEIGH_ADD(Add Entry)
            NETDEV_UP>NETDEV_UP]                 --> NEIGH_DEL(Remove Entry)
            NEIGH_ADD                            --> NEIGH[(Table of Deleted Neighbours)]
            NEIGH_DEL                            --> NEIGH
            NEIGH_READ[Read entries]             --> NEIGH
        end

        NETLINK_RCV --> ROUTE_ADD
        NETLINK_RCV --> ROUTE_DEL
        NETLINK_RCV --> ROUTE_FLUSH
        NETLINK_RCV --> ROUTE_SHOW

        subgraph Backup Route Configuration
            ROUTE_ADD(Add Entry)               --> ROUTES[(Routing Table)]
            ROUTE_DEL(Delete Entry)            --> ROUTES
            ROUTE_FLUSH(Delete all Entries)    --> ROUTES
            ROUTE_SHOW(Show all Entries)       --> ROUTES
            ROUTE_READ(Look for Backup Routes) -->ROUTES
        end
    end

    subgraph ti-mfa-conf commandline tool
        TI_MFA_CONF_ADD[/ti-mfa-conf add/]     --> NETLINK_SEND(Send Netlink Message)
        TI_MFA_CONF_DEL[/ti-mfa-conf del/]     --> NETLINK_SEND(Send Netlink Message)
        TI_MFA_CONF_FLUSH[/ti-mfa-conf flush/] --> NETLINK_SEND(Send Netlink Message)
        TI_MFA_CONF_SHOW[/ti-mfa-conf show/]   --> NETLINK_SEND(Send Netlink Message)
    end

    NETLINK_SEND --> NETLINK_SOCKET
    NETLINK_SOCKET --> NETLINK_RCV(Receive Netlink Message)
```
* PHP: [Penultimate hop popping](https://www.rfc-editor.org/rfc/rfc3031.html#section-3.16)


### Packet Header in Case of Link Failure
```
L2 Header | MPLS Shim Header(s) | MPLS Shim Header with Extension Label (15) | TI-MFA Header(s) | L3 Header
```

### Link Failure Header (TI-MFA Header)
```c
struct ti_mfa_shim_hdr {
    unsigned char link_source[ETH_ALEN];
    unsigned char link_dest[ETH_ALEN];
    unsigned char node_source[ETH_ALEN];
    u8            bos;
};
```

## Tests

The test topologies are configured with static routes.

### Testbed 1
Vagrant boxes with the topology from [^1] :
```mermaid
graph TB
    t   --- v_l
    v_l --- v_m
    v_m --- v_r
    t   --- v_m
    t   ---v_r
```
### Testbed 3
Vagrant boxes with the topology from [^2] :
```mermaid
graph TB
    B ---|3| C
    A ---|1| B
    A ---|2| C
    D ---|6| E
    C ---|5| E
    B ---|4| D
    D ---|7| Z
    E ---|8| Z
```

# Bibliography
[^1]: https://www.univie.ac.at/ct/stefan/gi18.pdf
[^2]: https://conferences.sigcomm.org/sosr/2017/papers/sosr17-demo-sr.pdf
