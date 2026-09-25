@id("20-rules#1")
forbid (principal, action, resource)
when { context.suspended == true };

@id("20-rules#2")
permit (principal, action == Action::"read", resource);

@id("20-rules#3")
permit (principal, action == Action::"read", resource == Document::"42");
