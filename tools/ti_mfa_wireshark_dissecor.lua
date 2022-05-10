ti_mfa_protocol = Proto("TI-MFA", "TI-MFA Protocol")

link_source = ProtoField.ether("TI-MFA.source", "Link Source")
link_dest = ProtoField.ether("TI-MFA.dest", "Link Destination")
node_source = ProtoField.ether("TI-MFA.node_source", "Node Source")
bos = ProtoField.bool("TI-MFA.bos", "Bottom of Stack")

ti_mfa_protocol.fields = {
  link_source, link_dest, node_source, bos
}

function ti_mfa_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  local length = buffer:len()
  pinfo.cols.protocol = ti_mfa_protocol.name

  local subtree = tree:add(ti_mfa_protocol, buffer(), "TI-MFA Protocol Data")

  subtree:add(link_source, buffer(0,6))
  subtree:add(link_dest, buffer(6, 6))
  subtree:add(node_source, buffer(12, 6))
  subtree:add(bos, buffer(18, 1))

  local ip_withoutfcs = Dissector.get("icmp")

  ip_withoutfcs(buffer(19, length - 19):tvb(), pinfo, tree)
end

mpls_table = DissectorTable.get("mpls.label")
mpls_table:add(15, ti_mfa_protocol)
