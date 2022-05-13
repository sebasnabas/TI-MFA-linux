ti_mfa_protocol = Proto("TI-MFA", "TI-MFA Protocol")

f_link_source = ProtoField.ether("TI-MFA.source", "Link Source")
f_link_dest = ProtoField.ether("TI-MFA.dest", "Link Destination")
f_node_source = ProtoField.ether("TI-MFA.node_source", "Node Source")
f_bos = ProtoField.bool("TI-MFA.bos", "Bottom of Stack")

ti_mfa_protocol.fields = {
  f_link_source, f_link_dest, f_node_source, f_bos
}

function ti_mfa_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  local length = buffer:len()
  pinfo.cols.protocol = ti_mfa_protocol.name

  local offset = 0;
  local link_failures = 0;
  local is_bos = false
  local lf_size = 19

  while (not is_bos)
  do
    local subtree = tree:add(ti_mfa_protocol, buffer(), "TI-MFA Link Failure Header")
    subtree:add(f_link_source, buffer(offset, 6))
    subtree:add(f_link_dest, buffer(offset + 6, 6))
    subtree:add(f_node_source, buffer(offset + 12, 6))
    subtree:add(f_bos, buffer(offset + 18, 1))

    is_bos = buffer(offset + 18, 1):uint() == 1

    offset = offset + lf_size
    link_failures = link_failures + 1
  end

  local ip_withoutfcs = Dissector.get("ip")

  ip_withoutfcs(buffer(offset, length - (lf_size * link_failures)):tvb(), pinfo, tree)
end

mpls_table = DissectorTable.get("mpls.label")
mpls_table:add(15, ti_mfa_protocol)
