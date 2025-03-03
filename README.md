## Vultr DNS provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Vultr DNS](https://www.vultr.com/docs/introduction-to-vultr-dns/).

### Installation

#### Command line

```
pip install octodns-vultr
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-vultr==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/izzoa/octodns-vultr.git@main#egg=octodns_vultr
```

### Configuration

```yaml
providers:
  vultr:
    class: octodns_vultr.VultrProvider
    # Your Vultr API token (required)
    token: env/VULTR_API_TOKEN
```

### Support Information

#### Records

VultrProvider supports A, AAAA, CAA, CNAME, MX, NS, SRV, and TXT

#### Root NS Records

VultrProvider supports full root NS record management.

#### Dynamic

VultrProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
