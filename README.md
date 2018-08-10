# Encrypt filter plugin for Embulk

Converts columns using an encryption algorithm such as AES.

Encrypted data is encoded using base64. For example, if you have following input records:

    id,password,comment
    1,super,a
    2,secret,b

You can apply encryption to password column and get following outputs:

    id,password,comment
    1,ayxU9lMA1iASdHGy/eAlWw==,a
    2,v8ffsUOfspaqZ1KI7tPz+A==,b

## Overview

* **Plugin type**: filter

## Configuration

- **algorithm**: encryption algorithm (see below) (enum, required)
- **column_names**: names of string columns to encrypt (array of string, required)
- **key_type**: encryption key (enum, optional, default: inline), can be either "inline" or "s3"
- **key_hex**: encryption key (string, required if key_type is inline)
- **iv_hex**: encryption initialization vector (string, required if mode of the algorithm is CBC and key_type is inline)
- **output_encoding**: the encoding of encrypted value, can be either "base64" or "hex" (base16)
- **aws_params**: AWS/S3 parameters (hash, required if key_type is s3)
    - **region**: a valid AWS region
    - **access_key**: a valid AWS access key
    - **secret_key**: a valid AWS secret key
    - **bucket**: a valid S3 bucket
    - **path**: a valid S3 key (S3 file path)
    
## Algorithms

Available algorithms are:

* **AES-256-CBC** (recommended)
* AES-192-CBC
* AES-128-CBC
* AES-256-ECB
* AES-192-ECB
* AES-128-ECB

AES-256-CBC is the recommended algorithm. The other algorithms are prepared for compatibility with other components (see below "Decrypting data" section).

## Generating key and iv

### Using standard PBKDF2 Password-based Encryption algorithm

PBKDF2 is a standard (PKCS #5) algorithm to generate key and iv from a password.

To generate it, you can use [genkey.rb](https://raw.githubusercontent.com/embulk/embulk-filter-encrypt/master/genkey.rb) script.

You save above text as "genkey.rb", and run it as following:

    $ ruby genkey.rb AES-256-CBC "my-pass-wo-rd"

It shows key and iv as following:

    key=D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42
    iv =2A1D6BD59D2DB50A59364BAD3B9B6544

### Using openssl EVP_BytesToKey algorithm

You can use `openssl` EVP_BytesToKey algorithm to generate key and iv from a password. If you use AES-256-CBC cipher algorithm, you type following command:

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

You can use PostgreSQL's `decrypt_iv` or `decrypt` function to decrypt values (provided as pgcrypto extension). If you use CBC,

    decrypt_iv(decode(encrypted_column, 'base64'), decode('here_is_key_hex', 'hex'), decode('here_is_iv_hex', 'hex'), 'aes')

If you use ECB,

    decrypt(decode(encrypted_column, 'base64'), decode('here_is_key_hex', 'hex'), 'aes')

<!-- This doesn't work. why?
### MySQL

You can use MySQL's `AES_DECRYPT` function to decrypt values. If you use CBC,

    AES_DECRYPT(FROM_BASE64(encrypted_column), unhex('here_is_key_hex'), unhex(here_is_iv_hex'))

If you use ECB,

    AES_DECRYPT(FROM_BASE64(encrypted_column), unhex('here_is_key_hex'))
-->

<!-- not confirmed yet
### Hive

You can use Hive's `aes_decrypt(input binary, key binary)` function (available since Hive 1.3.0) to decrypt values. But because Hive doesn't support CBC, you need to use AES-256-ECB, AES-192-ECB, or AES-128-ECB. Function call is:

    aes_decrypt(unbase64(encrypted_column), unhex('here_is_key_hex'))
-->

## Example

* Inline key type

```yaml
filters:
  - type: encrypt
    algorithm: AES-256-CBC
    column_names: [password, ip]
    key_hex: 098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05
    iv_hex: C9DD4BB33B827EB1FBA1B16A0074D460
    output_encoding: hex
```

* S3 key type

```yaml
filters:
  - type: encrypt
    algorithm: AES-256-CBC
    column_names: [password, ip]
    output_encoding: hex
    key_type: s3
    aws_params:
      region: us-east-2
      access_key: XXXXXXXXXXXXXXXXXXXX
      secret_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      bucket: com.sample.keys
      path: key.aes
```

## Build

```
$ ./gradlew gem  # -t to watch change of files and rebuild continuously
```
