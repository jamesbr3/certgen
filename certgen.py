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

#import yaml
from ruamel.yaml import YAML
yaml = YAML()

#
# load YAML config; return as nested python object
#
def load_config(config_file):
  # pip install munch
  from munch import Munch
  with open(config_file) as f:
    y = yaml.load(f)
    return Munch.fromDict(y)

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

WORK_DIR = "work"

def cert_role_string(cr):
  return f'1.3.6.1.4.1.50530.1.1:non-critical={CERT_ROLES[cr]}'

#
# http://openssl.cs.utah.edu/docs/apps/x509v3_config.html
# for openssl, change from "CN=Corda, OU=Blah" to "/CN=Corda/OU=Blah"
#def x509_to_openssl(dn):
#  return re.sub(r'(^|[,]\s*)([A-Z]+)=', lambda x:'/'+x.group(2)+'=',dn)

#
# Format the certificate extensions required by keytool
#
def extensions_str(cert):
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

def create_cert(config, cert, executor):
   
  store = config.stores[cert.store]

  keyfile  = os.path.normpath(f'{WORK_DIR}/{cert.alias}.key')
  csrfile  = os.path.normpath(f'{WORK_DIR}/{cert.alias}.csr')
  crtfile  = os.path.normpath(f'{WORK_DIR}/{cert.alias}.crt')
  rootfile = os.path.normpath(f'{WORK_DIR}/root.crt')
  
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

  # create self-signed keypair ( & cert)
  cmd1 = f'keytool -genkeypair -dname "{cert.subject}" -alias {cert.alias} -keyalg EC -keysize 256 -keystore {store.file} -storepass {store.password} -keypass {cert.key.password} -v'
  cmd1 = cmd1 + extensions_str(cert)
  executor(cmd1)

  # create CSR for issuer to sign
  cmd2 = f'keytool -certreq -alias {cert.alias} -file {csrfile} -keystore {store.file} -storepass {store.password} -keypass {cert.key.password} -v'
  executor(cmd2)

  # sign the CSR
  cmd3 = f'keytool -gencert -alias {issuer} -ext honored=all -infile {csrfile} -outfile {crtfile} -keystore {castore.file} -storepass {castore.password} -keypass {issuerpass} -v'
  cmd3 = cmd3 + extensions_str(cert)
  executor(cmd3)

  # generate certpath
  
  
  #executor(cmd4)

  # update with the signed copy
  cmd4 = f'keytool -importcert -alias {cert.alias} -keystore {store.file} -storepass {store.password} -noprompt -trustcacerts -keypass {cert.key.password} -v'

  cat = 'type' if os.name == 'nt' else 'cat'  
  cmd4 = f'{cat} {crtfile} {rootfile} | {cmd4}'
  
  executor(cmd4)
  


def apply_store_defaults(store, alias):
  try:    
    store.__getattr__('password')
  except AttributeError:
    store['password'] = 'password'
    
  pass

def apply_cert_defaults(cert, alias):
  if not hasattr(cert, 'alias'):
    cert.alias = alias

  if not hasattr(cert, 'password'):
    cert.password = 'password'

def generate(config, executor):

  # preprocess the stores section
  for store in config.stores:
    store = config.stores[store]
    apply_store_defaults(store, 0)  
  
  # preprocess the certificates section
  for alias in config.certificates:    
    cert = config.certificates[alias]    
    apply_cert_defaults(cert, alias)
    
  # generate the certificates
  for alias in config.certificates:
    cert = config.certificates[alias]                  
    print(f'@echo ' + '-'*100)
    print(f'@echo generating: {cert.alias} - "{cert.subject}"')
    print(f'@echo ' + '-'*100)
    create_cert(config, cert, executor)

def execute(cmd):
  from colorama import Fore, Back, Style
  from termcolor import colored

  print(Fore.CYAN + cmd, flush=True)
  print(Style.RESET_ALL)
  #print(colored(cmd, 'cyan'))
  
  #print('\033[31m' + 'hello')

  result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)#stdout=subprocess.PIPE)
  print(result.stdout.decode('utf-8'))
  #print(result.stdout.read())

def main(args):

  from colorama import init
  #init(convert=True)
  init(strip=False)

  WORK_DIR = args.workdir
  os.makedirs(WORK_DIR, exist_ok=True)

  cert_config = load_config(args.config)

  if args.execute:
    executor = execute
  else:
    executor = print

  generate(cert_config, executor)

parser = argparse.ArgumentParser('Certificate hierarchy generator')
parser.add_argument('--config',   help = 'configuration file in YAML format', required=True)
parser.add_argument('--workdir',  help = 'working directory', dest='workdir', default='work')
parser.add_argument('--execute',  help = 'working directory', dest='execute', default=False, action='store_true')
args = parser.parse_args()  

main(args)