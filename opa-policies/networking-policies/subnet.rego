package azure.network
import future.keywords.contains
import future.keywords.if

#Rule 1 : Subnets are associated with network security groups

# Helper: checks whether a subnet has an associated NSG in this plan
subnet_has_nsg(subnet_name) if {
    assoc := input.resource_changes[_]
    assoc.type == "azurerm_subnet_network_security_group_association"
    contains(assoc.address, subnet_name)
}

# Rule 2: Subnets must be associated with a Network Security Group (Defender for Cloud)
deny contains msg if {
    r := input.resource_changes[_]
    r.type == "azurerm_subnet"
    r.change.actions[_] in {"create", "update"}
    subnet_name := split(r.address, ".")[1]
    not subnet_has_nsg(subnet_name)
    msg := sprintf(
        "[NETWORK] '%v': subnet must be associated with a Network Security Group — deploy an azurerm_subnet_network_security_group_association resource",
        [r.address]
    )
}