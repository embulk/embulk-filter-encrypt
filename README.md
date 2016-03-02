# Encrypt filter plugin for Embulk

Converts columns using an encryption algorithm such as AES.

Encrypted value is a base64 string.

## Overview

* **Plugin type**: filter

## Configuration

- **algorithm**: encryption algorithm (see below) (enum, required)
- **column_names**: names of string columns to encrypt (array of string, required)
- **key_hex**: encryption key (string, required)
- **iv_hex**: encyrption initialization vector (string, required if mode of the algorithm is CBC)

## Algorithms

Supported algorithms are:

* **AES-256-CBC** (recommended)
* AES-192-CBC
* AES-128-CBC
* AES-256-ECB
* AES-192-ECB
* AES-128-ECB

AES-256-CBC is the recommended algorithm. The other algorithms are prepared for compatibility with other components (see below "Decrypting data" section).

## Generating key and iv

### Using standard PBKDF2 Password-based Encryption algorithm

PBKDF2 is a standard algorithm to generate key and iv from a password.

To generate it, you can use following ruby script:

    #/usr/bin/env ruby
    require 'openssl'
    
    if ARGV.length != 2
      puts "Usage: #{$0} <algorithm> <password>"
      exit 1
    end
    
    cipher = OpenSSL::Cipher.new ARGV[0]
    password = ARGV[1]
    
    cipher.encrypt
    iv = cipher.random_iv
    salt = OpenSSL::Random.random_bytes(16)
    key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 20000, cipher.key_len, OpenSSL::Digest::SHA256.new)
    
    puts "key=#{key.unpack('H*')[0].upcase}"
    puts "iv =#{iv.unpack('H*')[0].upcase}"

You save above text as "genkey.rb", and run it as following:

    $ ruby genkey.rb AES-256-CBC "my-pass-wo-rd"

It shows key and iv as following:

    key=FF69F0CADDFFA76CC08C629DFAEFFF3EA9650A2320FFE126D88FF9100446249F
    iv =50D6267A078EFACD00CAEAA2A4064FC0

### Using openssl command

You can use `openssl` command to generate key and iv from a password. If you use AES-256-CBC algorithm, you type following command:

    $ echo secret | openssl enc -aes-256-cbc -a -nosalt -p

You will be asked to enter password. Then it shows key and iv:

    key=DAFFED346E29C5654F54133D1FC65CCB5930071ACEAF5B64A22A11406F467DC9
    iv =C92D28D70B4440DA3F0F05577ECFEE54
    6aEGvMrGx7tODkPF7x5Yog==

You can copy key and iv to key_hex and iv_hex parameters.

## Decrypting data

### openssl command

You can use openssl command as following:

    $ echo <encrypted value> | openssl enc -d -base64 | openssl enc -aes-256-cbc -d -K <key> -iv <iv>

For example:

    $ echo 6aEGvMrGx7tODkPF7x5Yog== | openssl enc -d -base64 | openssl enc -aes-256-cbc -d -K DAFFED346E29C5654F54133D1FC65CCB5930071ACEAF5B64A22A11406F467DC9 -iv C92D28D70B4440DA3F0F05577ECFEE54
    secret

### PostgreSQL

To decrypt value using PostgreSQL (provided as pgcrypto extension), you can use CBC. If you use CBC, you can decrypt data using `decrypt_iv(decode(encrypted_column, 'base64'), decode('here_is_key_hex', 'hex'), decode('here_is_iv_hex', 'hex'), 'aes')`. If you use ECB, you can decrypt data using `decrypt(decode(encrypted_column, 'base64'), decode('here_is_key_hex', 'hex'), 'aes')`

<!-- This doesn't work. why?
### MySQL

To decrypt value using MySQL, you can use CBC. If you use CBC, you can decrypt data using `AES_DECRYPT(FROM_BASE64(encrypted_column), unhex('here_is_key_hex'), unhex(here_is_iv_hex'))`. If you use ECB, you can decrypt data using `AES_DECRYPT(FROM_BASE64(encrypted_column), unhex('here_is_key_hex'))`.
-->

<!-- not confirmed yet
### Hive

To decrypt value using Hive's `aes_decrypt(input binary, key binary)` function (available since Hive 1.3.0), you need to use AES-256-ECB, AES-192-ECB, or AES-128-ECB. You can decrypt data using `aes_decrypt(unbase64(encrypted_column), unhex('here_is_key_hex'))` function call.
-->

## Example

```yaml
filters:
  - type: encrypt
    column_names: [password, ip]
    key_hex: 098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05
    iv_hex: C9DD4BB33B827EB1FBA1B16A0074D460
```


## Build

```
$ ./gradlew gem  # -t to watch change of files and rebuild continuously
```
