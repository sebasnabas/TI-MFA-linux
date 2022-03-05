# TI-MFA-linux

A Linux kernel module for the Topology Independent Multi Failure Alternate (TI-MFA) algorithm from [Foerster et al.](https://www.univie.ac.at/ct/stefan/gi18.pdf)

## Architecture
Needs Kernel >= 5.16.0 (For Egress Hook)
```mermaid
graph LR;
    IP[Incoming Packet] --> A;
    A[Netfilter Ingress Hook] --> B{ROUTING};
    B --> C[Netfilter Egress Hook];
    D[Netlink Routing Socket] --set deleted next hops--> C;
    C --set TI-MFA header--> OP[Outgoing Packet];
```