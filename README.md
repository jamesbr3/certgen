# certgen
Corda Certificate Generator

`certgen` is a python tool to create certificate hierarchies. It is a wrapper around `keytool` and uses a 
configuration file that can specify full certificate hierarchies.

## Installation
certgen requires the Java `keytool` to be on the path. Install the Java JDK 

run `pip setup -r requirements.txt` to install python dependencies

## Usage

```
python certgen.py --config CONFIG [--workdir=WORKDIR] [--execute]
```

* `config` - path to the certificate configuration file (see Examples below)
* `workdir` - (optional) path to store temporary files. Default is `./work`
* `execute` - execute

Example:
```
python certgen.py --config examples/node_certs.conf --execute
```


## Examples

See `examples\node_certs.conf` and `examples\netmap_cert.conf`

## Certificate Configuration

Certificate configuration is specified in a YAML file. There are two basic sections that need to be specified

### Stores
keystores must be specified in the `stores` section:
```
stores: {
  caKeyStore: {
    file : "./examples/cordadevcakeys.jks",
    password : "cordacadevpass"
  },
  destStore : {
    file : "./work/destkeystore.jks",
    password : "keystorepass"
  }
}
```
### Certificates
```
certificates : {
   certalias: {
       alias: "alias"
       subject: "X500 name"
       store: "destStore"
       issuer : "caKeyStore.cordaintermediateca:cordacadevkeypass",
       key : {
            alias : "identity-private-key",
            password : "cordacadevpass",
            algorithm : "ECDSA_SECP256R1_SHA256"
       },
       extensions: {
        BasicConstraints: "critical,ca:false,pathlen:0",
        KeyUsage: "keyCertSign,cRLSign,digitalSignature",
        ExtendedKeyUsage: "serverAuth,clientAuth"        
      }       
   }
}
```
Certificate hierarchies are created by specifying an `issuer` certificate. The issuer can be another defined certificate, 
or can be stored in an external keystore

Certificate extensions are passed directly to `keytool` using the `addext` option. Refer to keytool documentation for details.
