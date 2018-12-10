# DNS-over-HTTPS NSS module

A hostname resolver which uses DNS-over-HTTPS.

Resolver of last resort, useful as an alternative when the DNS
infrastructure starts acting up. It's hardcoded to Cloudflare's
__1.1.1.1__ and only looks for IPv4 addresses at present. To use
it, you must build and install it in a specific way, while also
changing the system's NSS (Name Service Switch) configuration;
see below. No additional service is required on the system.

## Building and installing

An NSS module must be compiled as a shared object with an expected
filename _and_ internal soname (Shared Object Name). For a service
named __doh__, NSS code will search for the file *libnss_doh.so.2*
in the library search path, with the identical soname. Since Cargo
won't let you set either of those names satisfactorily (see issues
[#1706](https://github.com/rust-lang/cargo/issues/1706) and
[#5045](https://github.com/rust-lang/cargo/issues/5045)), it must
be done after the build.

For the name of the file itself, simple renaming will suffice. For
setting the soname, you need the `patchelf` utility (Ubuntu's
universe or CentOS/Fedora EPEL repository). The steps for building
are:

```shell
cargo build --release
patchelf --set-soname libnss_doh.so.2 target/release/libdohres.so
```

Installing on Ubuntu 64-bit:

```shell
sudo install -m 644 -o root -g root target/release/libdohres.so /lib/x86_64-linux-gnu/libnss_doh.so.2
```

Installing on CentOS 64-bit:

```shell
sudo install -m 755 -o root -g root target/release/libdohres.so /lib64/libnss_doh.so.2
```

## Configuring NSS

To use the service, its name must be specified in the line for the
`hosts:` database in */etc/nsswitch.conf*. On Ubuntu, you might use

```
hosts:          files mdns4_minimal [NOTFOUND=return] dns doh
```

This will try __doh__ last.

## Caveats

* Hardcoded to Cloudflare's __1.1.1.1__ resolver.

* Only IPv4 (`AF_INET`) lookups work.

* Reverse lookups (by address) are not supported.

* If the address is behind a CNAME chain, the final name should be
  set as the resolved canonical name. For simplicity, this is not done;
  the requested name is always returned.

* Every requested name is treated as an FQDN; short names and search
  paths are not supported.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
