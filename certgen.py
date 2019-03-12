#
# Corda Certificate Generator
# requires Java Keytool to be installed

# see also requirements.txt for Python dependencies
#

import sys
import re
import argparse
import os
import subprocess

from ruamel.yaml import YAML
yaml = YAML()
from munch import Munch

from colorama import Fore, Back, Style

CERT_ROLES = {
  "DOORMAN_CA":            "020101",
  "NETWORK_MAP":           "020102",
  "SERVICE_IDENTITY":      "020103",
  "NODE_CA":               "020104",
  "TLS":                   "020105",
  "LEGAL_IDENTITY":        "020106",
  "CONFIDENTIAL_IDENTITY": "020107",
  "NETWORK_PARAMETERS":    "020108"
}

def cert_role_string(cr):
    return f'1.3.6.1.4.1.50530.1.1:non-critical={CERT_ROLES[cr]}'

def execute(cmd):  
  print(Fore.CYAN + cmd, flush=True)
  print(Style.RESET_ALL)

  result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)#stdout=subprocess.PIPE)
  print(result.stdout.decode('utf-8'))
  print(result.stderr.decode('utf-8'))    

class CertGenerator:

  def __init__(self, workdir = 'work'):
    self.WORK_DIR = workdir
    os.makedirs(workdir, exist_ok=True)

  def __mkpath(self, file):
    file = os.path.normpath(file)
    print('creating: ' + file)
    parts = os.path.split(file)
    os.makedirs(parts[0], exist_ok=True)
    return file

  #
  # http://openssl.cs.utah.edu/docs/apps/x509v3_config.html
  #def x509_to_openssl(dn):
  #  change from "CN=Corda, OU=Blah" to "/CN=Corda/OU=Blah"
  #  return re.sub(r'(^|[,]\s*)([A-Z]+)=', lambda x:'/'+x.group(2)+'=',dn)

  #
  # Format the certificate extensions required by keytool
  #
  def __extensions_str(self, cert):
    exts = ''

    # cert role
    if hasattr(cert, 'role'):
      exts = exts + f' -ext {cert_role_string(cert.role)}'

    # add extensions
    for extn in cert.extensions:
      extv = cert.extensions[extn]    
      if extv.startswith('critical'):
        extn += ':critical'
        extv = extv[9:]

      exts = exts + f' -ext "{extn}={extv}"'  

    return exts

  #
  # load YAML config; return as nested python object
  #
  def load_config(self, config_file, params):  
    
    print(f'Parameter substitutions: {params}')

    with open(config_file) as f:
      p = re.compile('.*\".*{.*}.*\"')
      conf = ""
      for line in f:
        if p.match(line):
          try:
            line = line.format(**params)
          except KeyError as e:
            print(f'{e} must be defined: --param {str(e)[1:-1]}:<value> ')
            exit(1)
        conf = conf + line

      #print(conf)
      #exit(0)
      y = yaml.load(conf)
      return Munch.fromDict(y)


  def create_cert(self, config, cert, executor):
    """ create certificate based on the specified config """   
    store = config.stores[cert.store]

    outfile  = self.__mkpath(store.file)
    keyfile  = self.__mkpath(f'{self.WORK_DIR}/{cert.alias}.key')
    csrfile  = self.__mkpath(f'{self.WORK_DIR}/{cert.alias}.csr')
    crtfile  = self.__mkpath(f'{self.WORK_DIR}/{cert.alias}.crt')
    rootfile = self.__mkpath(f'{self.WORK_DIR}/root.crt')
    
    # find the signer. If it is not explicitly in config
    if '.' in cert.issuer:
      castore = cert.issuer.split('.')[0]
      castore = config.stores[castore]
      issuer  = cert.issuer.split('.')[1]
    else:
      castore = store
      issuer  = cert.issuer

    if ':' in issuer:
      issuerpass = issuer.split(':')[1]
      issuer     = issuer.split(':')[0]
    else:
      issuerpass = issuer.key.password

    cmd0 = f'keytool -exportcert -alias cordarootca -keystore {castore.file} -file {rootfile} -storepass {castore.password} -v'
    executor(cmd0)

    # delete the existing keypair
    cmd0 = f'keytool -delete -alias {cert.alias} -keystore {outfile} -storepass {castore.password}'
    executor(cmd0)

    # create self-signed keypair ( & cert)
    cmd1 = f'keytool -genkeypair -dname "{cert.subject}" -alias {cert.alias} -keyalg EC -keysize 256 -keystore {outfile} -storepass {store.password} -keypass {cert.key.password} -v'
    cmd1 = cmd1 + self.__extensions_str(cert)
    executor(cmd1)

    # create CSR for issuer to sign
    cmd2 = f'keytool -certreq -alias {cert.alias} -file {csrfile} -keystore {outfile} -storepass {store.password} -keypass {cert.key.password} -v'
    executor(cmd2)

    # sign the CSR
    cmd3 = f'keytool -gencert -alias {issuer} -ext honored=all -infile {csrfile} -outfile {crtfile} -keystore {castore.file} -storepass {castore.password} -keypass {issuerpass} -v'
    cmd3 = cmd3 + self.__extensions_str(cert)
    executor(cmd3)

    # update with the signed copy
    cmd4 = f'keytool -importcert -alias {cert.alias} -keystore {outfile} -storepass {store.password} -noprompt -trustcacerts -keypass {cert.key.password} -v'

    cat = 'type' if os.name == 'nt' else 'cat'  
    cmd4 = f'{cat} {crtfile} {rootfile} | {cmd4}'
    
    executor(cmd4)
  

  def __apply_store_defaults( store, alias):
    try:    
      store.__getattr__('password')
    except AttributeError:
      store['password'] = 'password'
      
    pass

  def __apply_cert_defaults(cert, alias):
    if not hasattr(cert, 'alias'):
      cert.alias = alias

    if not hasattr(cert, 'password'):
      cert.password = 'password'

  def generate(self, config, executor=execute):

    # preprocess the stores section
    for store in config.stores:
      store = config.stores[store]
      CertGenerator.__apply_store_defaults(store, 0)  
    
    # preprocess the certificates section
    for alias in config.certificates:    
      cert = config.certificates[alias]    
      CertGenerator.__apply_cert_defaults(cert, alias)
      
    # generate the certificates
    for alias in config.certificates:
      cert = config.certificates[alias]                  
      print(Fore.BLACK + Style.BRIGHT + f'@echo ' + '-'*100)
      print(Fore.BLACK + Style.BRIGHT + f'@echo generating: {cert.alias} - "{cert.subject}"')
      print(Fore.BLACK + Style.BRIGHT + f'@echo ' + '-'*100)
      print(Style.RESET_ALL)
      self.create_cert(config, cert, executor)


def main(args):

  from colorama import init
  init(strip=False)


  # build diction of parameter substitutions
  args.params = [y for x in args.params for y in x]  
  params = {}
  for p in args.params:
    nv = p.split(':')
    params[nv[0]] = nv[1]
  

  certgen = CertGenerator(args.workdir)

  cert_config = certgen.load_config(args.config, params)

  if args.execute:
    executor = execute
  else:
    executor = print

  certgen.generate(cert_config, executor)


if __name__ == "__main__":

  parser = argparse.ArgumentParser('Certificate hierarchy generator')
  parser.add_argument('--config',   help = 'configuration file in YAML format', required=True)
  parser.add_argument('--workdir',  help = 'working directory', dest='workdir', default='work')
  parser.add_argument('--execute',  help = 'working directory', dest='execute', default=False, action='store_true')
  parser.add_argument('--param',  help = 'parameter substitutions. [A:B]', dest='params', nargs='+', action='append', default=[])
  #parser.add_argument('--render',  help = 'render config and exit', default=False, action='store_true')
  args = parser.parse_args()  

  main(args)