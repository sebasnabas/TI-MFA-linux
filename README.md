# TI-MFA-linux

**Note:** TI-MFA is currently only implemented for MPLS. Srv6 is not supported (yet).

A Linux kernel module for the Topology Independent Multi Failure Alternate (TI-MFA) algorithm from [^1] ("described from the viewpoint of the node v where the packet hits another failed link"):
>   1) Flush the label stack except for the destination t.
>   2) Based on all link failures stored in the packet header,
>       determine the shortest path P to the destination t in the
>       remaining network G′.
>   3) Add segments to the label stack of the packet as follows:
>       • Index the nodes on P as v = v1, v2, . . . , vx = t.
>           Compute the node vi on P with the highest index s.t. the shortest path from v is identical in G′ (with failures) and G (without failures) and set it as the top of the label stack.
>           If this node is v, push the link (v1, v2 = vi) as the top of the label stack.
>           For the second item on the label stack, start over with vi as the starting node, etc., until vi = t.

## Implementation

### Architecture
Needs Kernel `>= 5.16.0` (For Egress Hook)
```mermaid
graph TB
    IP((Incoming Packet)) --> IH_IF{"if (MPLS)"}

    subgraph NF_IH["Netfilter Ingress Hook"]
        IH_IF        -->|true| IH_IF_TI_MFA{"if (BOS && MPLS Extension Label)"}
        IH_IF_TI_MFA -->|true| A(Remove TI-MFA headers)
    end

    IH_IF        -->|false| R[Kernel Routing]
    IH_IF_TI_MFA -->|false| R
    A            -->        R
    R            -->|false| EH_IF{"if (MPLS)"}
    EH_IF        -->|false| OP((Outgoing Packet))

    subgraph NF_EH[Netfilter Egress Hook]
        EH_IF     -->|true| 1_TI_MFA(1. Flush MPLS and/or TI-MFA headers)
        1_TI_MFA  -->        2_TI_MFA(2. Get shortest path)
        2_TI_MFA  -->        SLF(Set local link failures)
        SLF       -->        IF_LF_PHP{"if (Local Link Failures && NOT PHP)"}
        IF_LF_PHP -->|true| 3_TI_MFA(3. Set label stack)
        IF_LF_PHP -->|false| PHP(Set package type to IP)
    end

    SLF     -.-> NEIGH_READ
    3_TI_MFA -->  OP
    PHP      -->  OP

    subgraph Netdev Notifier
        NETDEV_GOING_DOWN>NETDEV_GOING_DOWN] --> NEIGH_ADD(Add Entry)
        NETDEV_UP>NETDEV_UP]                 --> NEIGH_DEL(Remove Entry)
        NEIGH_ADD                            --> NEIGH[(Table of Deleted Neighbours)]
        NEIGH_DEL                            --> NEIGH
        NEIGH_READ[Read entries]             --> NEIGH
    end
```
* PHP: [Penultimate hop popping](https://www.rfc-editor.org/rfc/rfc3031.html#section-3.16)


### Packet Header in Case of Link Failure
```
L2 Header | MPLS Header(s) | MPLS Header with Extension Label (15) | MPLS Destination Header | TI-MFA Header(s) | L3 Header
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
### Testbed 1
Vagrant boxes with the topology from [^1] :
```mermaid
graph TB
    t --- v_l
    v_l --- v_m
    v_m --- v_r
    t --- v_m
    t ---v_r
```
 * Problems:
    + When using frr with ospf the routes to the directly connected nodes are not MPLS routes.

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
