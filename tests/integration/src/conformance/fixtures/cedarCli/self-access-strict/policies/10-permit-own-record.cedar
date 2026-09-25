@id("10-permit-own-record")
permit (principal, action, resource)
when { resource == principal && principal.dept == "eng" };
