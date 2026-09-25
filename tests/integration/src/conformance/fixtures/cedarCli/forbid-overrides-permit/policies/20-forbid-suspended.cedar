@id("20-forbid-suspended")
forbid (principal, action, resource)
when { context.suspended == true };
