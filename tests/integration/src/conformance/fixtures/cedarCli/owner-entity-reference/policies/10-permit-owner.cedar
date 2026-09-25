@id("10-permit-owner")
permit (principal, action, resource)
when { resource.owner == principal };
