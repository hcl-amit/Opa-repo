Rule 1 : Azure DDoS Network Protection is enabled on virtual networks for azure bastion

ddos_protection_enabled(r) if {
    plan := r.change.after.ddos_protection_plan[_]
    plan.enable == true
}

deny contains msg if {
    r := input.resource_changes[_]
    r.type == "azurerm_virtual_network"
    r.change.actions[_] in {"create", "update"}
    not ddos_protection_enabled(r)
    msg := sprintf(
        "[NETWORK] [DDOS] '%v': Azure DDoS Network Protection must be enabled — attach a ddos_protection_plan block with enable = true",
        [r.address]
    )
}