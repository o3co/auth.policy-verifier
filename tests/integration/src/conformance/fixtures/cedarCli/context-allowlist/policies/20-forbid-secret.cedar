@id("20-forbid-secret")
forbid (principal, action, resource)
when { context has secret };
