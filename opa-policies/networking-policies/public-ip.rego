package azure.networking
import future.keywords.contains
import future.keywords.if

# Rule 1 : Public IP addresses are Evaluated on a Periodic Basis

deny contains msg if {
    r := input.resource_changes[_]
    r.type == "azurerm_public_ip"
    r.change.actions[_] in {"create", "update"}
    not r.change.after.tags
    msg := sprintf(
        "[NETWORK] '%v': Public IP must have tags — tags are required to support periodic evaluation and lifecycle tracking per Defender for Cloud",
        [r.address]
    )
}