# Encrypty
Simple GUI application for generating digital envelopes, seals and signatures.

The application uses OpenSSL's *libcrypto* library for the backend(actual encryption) and the *wxWidgets* library
for cross-platform GUI applications in C++.

## Requirements

- A compiler supporting C++17
- OpenSSL 1.1.1g
- wxWidgets 3.0 or higher

Both of the libraries were installed using the MSYS2 platform, along with the MinGW implementation, which was used
as the compiler.

The application itself can be compiled with the following compiler flags (for debug mode):
- -g
- -O0
- -Wall
- -std=c++17 
- -D_FILE_OFFSET_BITS=64
- -D__WXMSW__
- -fpermissive

And linker flags:
- -LC:/msys64/mingw64/lib 
- -pipe 
- -Wl,
- --subsystem,windows 
- -mwindows 
- -lwx_mswu_xrc-3.0 
- -lwx_mswu_webview-3.0 
- -lwx_mswu_stc-3.0
- -lwx_mswu_richtext-3.0 
- -lwx_mswu_ribbon-3.0 
- -lwx_mswu_propgrid-3.0 
- -lwx_mswu_aui-3.0 
- -lwx_mswu_gl-3.0 
- -lwx_mswu_html-3.0 
- -lwx_mswu_qa-3.0 
- -lwx_mswu_adv-3.0 
- -lwx_mswu_core-3.0 
- -lwx_baseu_xml-3.0 
- -lwx_baseu_net-3.0 
- -lwx_baseu-3.0

## .nos Files
In this *readme* file and in the application itself, .nos files are mentioned which are files used for the
college assignment this app was developed.
```
---BEGIN NOS CRYPTO DATA---
Variable_name:
    variable_data

Another_variable_name:
    More_variable_data
---END NOS CRYPTO DATA---
```

## BACKEND
The backend consits of a couple of files which handle the encryption logic of the application. It has a [file](backend/openssl_types_util.hpp) with helper types for OpenSSL, a B64 encoding [implementation](backend/base64.h), a [parser](backend/parser.hpp) for the *.nos* files described above, functions for generating random initialization vectors, symmetric keys, generci functions for RSA algorithms (signing, verification, encription, etc.) using *EVP_PKEY* functions
of OpenSSL, function for symmetric encryption and decryption ([encrypt](backend/encrypt.hpp)) and a function and helper class for message digests ([signature](backend/signature.hpp)).

## VM
The classes which are used to connect the backend and the frontend are in the [vm](vm) directory. Every one of the three main window pages has it's coresponding VM class with helper functions to access the backend functionalities. The VM classes are:
- The envelope VM class - [env_vm](vm/env_vm.h) - contains functions for sealing and opening a digital envelope
- The signature VM class - [sign_vm](vm/sign_vm.h) - contains functions for signing and verifying digital signatures
- The seal VM class - [seal_vm](vm/seal_vm.h) - contains functions for digitally sealing and opening a sealed digitally sealed envelope

## Frontend
The frontend directory consists of classes for each encription functionality: envelopes, signatures and seals.
It also contains an [app](frontend/app.h) class for required for wxWidgets apps, a class which represents the actual main window being displayed and other helper dialog classes which are used for reviewing and comparing files after some operations, i.e verifying a SHA sum.

### Envelope
The digital envelope [component](frontend/envelope_window.h) consists of smaller components for specifying parametrs of the symmetric and asymmetric encryption and the catual closing or opening an envelope.

In the symmetric encryption component a user can specify the type of algorithm to use, the size of the key and how consecutive blocks are handled (*CBC*, *CTR*, ...). It also requires the actual symmetric key and the initialization vector to be specified in hexadecimal, but they can be either loaded from *.nos* files or randomly generated.

The asymmetric part consists of fields for choosing a size for the asymmetric key, fields for the module and private and public exponents. The data can be directly entered, loaded from a *.nos* file or randomly generated if the key and public exponent are specified.

The last part of the envelope component consists of two columns of smaller components for either generating the envelope, which requires an input file which will be encrypted and an output file, while the other column consists of fields for specifying generated envelope *.nos* file and a file where the original message will be written (can be omitted).

### Signature
The [component](frontend/signature_window.h) for generating a digital signature is analogous to the envelope component, but has sub-components for picking a hash digest algorithm (different versions of SHA). It also contains two columns analogous to the previous component, but for generating and verifying signatures.

### Seal
The last [component](frontend/sign_window.h) is used for generating or opening digital seals and is a combination of the previous two components, because it requires both functionalities.
