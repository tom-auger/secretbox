[![Build status](https://ci.appveyor.com/api/projects/status/pra8fsvbarld7a2w?svg=true)](https://ci.appveyor.com/project/tom-auger/secretbox)

# SecretBox

<img align="right" src="logo.png">

SecretBox is a small .NET library for symmetric key encryption using the Gimli permutation. The SecretBox construction is a port of `hydro_secretbox` from [libhydrogen](https://github.com/jedisct1/libhydrogen). The Gimli primitive is a C# translation of the `c-ref` implementation of the Gimli permutation, for which the source code and specification can be obtained [here](https://gimli.cr.yp.to/).

The SecretBox source code is pure C# targeting .NET Standard 2.0 and licensed under ISC.

**Goals:**

* A pure C# code base targeting .NET Standard.
* Simple API that's easy to use and hard to misuse.
* Interoperable with [libhydrogen](https://github.com/jedisct1/libhydrogen).

**Non Goals:**

* NSA-proof security.
* Optimized for high performance.

## Installation

Add to your project via [nuget](https://www.nuget.org/packages/SecretBox/):

```
dotnet add package SecretBox
```

## Usage

```csharp
var sb = new SecretBox();
const string context = "test";

// Message to encrypt
var message = Encoding.UTF8.GetBytes("You are old, Father William");
const int messageId = 1;

// Generate a key
var key = new byte[SecretBox.KeyBytes];
sb.GenerateKey(key);

// Encrypt
var ciphertext = new byte[sb.CalculateCiphertextLength(message.Length)];
sb.Encrypt(ciphertext, message, message.Length, key, context, messageId);

// Decrypt
var decryptedMessage = new byte[sb.CalculateMessageLength(ciphertext.Length)];
sb.Decrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId);
```

### Contexts

The context is a string of maximum 8 characters that indicates what the ciphertext will be used for. The same message encrypted with a key in one context cannot be decrypted by the same key in a different context. This helps prevent security related bugs where encrypted data may be unintentionally decrypted and exposed in a different domain, e.g. by a separate application or service.

The context does not have to be secret, can be low entropy, and can safely be reused between messages. Examples include `logon`, `auth`, `docs`, `trades`. The context can also be a constant value within an application.

Using a context longer than 8 characters will throw a validation error.

### Message Ids

The message Id is an optional value that can be used when sending a sequence of messages. For example the first message may have message Id 1, the second 2, and so on. If the message Id is not specified then the default value 1 is used for both encryption and decryption.

A message cannot be decrypted with a message Id different to the one used during encryption. This can be used to ensure messages are received in the right order, or to reject duplicates.

The message Id can be any int64 value, so a timestamp or unique Id may also be used.

## Compiling from source

1. Clone the repository including submodules: 
    ```
    git clone --recurse-submodules https://github.com/tom-auger/secretbox.git
    ```
    There is one submodule located in 'tests/libhydrogen/libhydrogen' that pulls the [libhydrogen](https://github.com/jedisct1/libhydrogen) source code used by the integration tests. 

    If you cloned `SecretBox` without `--recurse-submodules` you can pull the submodule separately by running:

    ```
    git submodule init
    git submodule update
    ```
2. Open `SecretBox.sln`, do a build and verify all the tests pass.

Some of the unit tests verify integration with [libhydrogen](https://github.com/jedisct1/libhydrogen). To make it easy to test against the latest source there is an MSVC project to compile the libhydrogen source code. See the [README](tests/README.md) for details.

## Contributing

Feedback, suggestions, and pull requests are welcome, thanks!