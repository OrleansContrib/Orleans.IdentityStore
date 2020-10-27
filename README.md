# Orleans Identity Store

Leverage the sweet power of orleans to persist user credentials using grain storage.

## Getting Started

Once you've installed the nuget package, do the following:

SiloBuilder:

```
siloBuilder.UseOrleanIdentityStore() // Add identity store
```

### Storage Provider

The grain storage provider used is `OrleansIdentityStore`

Asp Core Startup:

```
// Add identity
services
    .AddDefaultIdentity<IdentityUser<Guid>>()
    // User orleans as the store
    .AddOrleansStores<IdentityUser<Guid>, IdentityRole<Guid>>();
```

### User Class

Your User class must subclass `IdentityUser<Guid>`

### Role Class

Your Role class must subclass `IdentityRole<Guid>`