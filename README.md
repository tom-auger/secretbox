# SecretBox

SecretBox is a small .NET library for symmetric key encryption using the Gimli permutation. The SecretBox construction is a port of `hydro_secretbox` from [libhydrogen](https://github.com/jedisct1/libhydrogen). The Gimli primitive is a C# translation of the `c-ref` implementation of the Gimli permutation, for which the source code and specification can be obtained [here](https://gimli.cr.yp.to/).

The SecretBox source code is pure C# targeting .NET Standard 2.0 and licensed under ISC.

**Goals:**

* A pure C# code base targeting .NET Standard.
* Simple API that's easy to use and hard to mis-use.
* Interoperable with [libhydrogen](https://github.com/jedisct1/libhydrogen).

**Non Goals:**

* NSA proof security.
* Optimized for high performance.

## Installation

Add to your project via nuget:

```
dotnet add package SecretBox
```

## Usage

```csharp
var sb = new SecretBox();
const string context = "test";

// Message to encrypt
var message = Encoding.UTF8.GetBytes("You are old Father William");
const int messageId = 1;

// Generate a key
var key = new byte[KeyBytes];
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

A context with more than 8 characters will throw a validation error.

### Message Ids

The message Id is an optional value that can be used when sending a sequence of messages. For example the first message can have message Id 1, the second 2, and so on. If the message Id is not specified then the default value 1 is used for both encryption and decryption.

A message cannot be decrypted with the wrong message Id, this can be used to ensure messages are received in the right order, or to reject duplicates.

The message Id can be any int64 value, so a timestamp or unique Id could also be used.

## Compiling from source

1. Clone the repository and submodules: 
```
git clone --recurse-submodules https://github.com/tom-auger/secretbox.git
```
2. Open `SecretBox.sln`, do a build and verify all the tests pass.

Some of the unit tests verify integration with [libhydrogen](https://github.com/jedisct1/libhydrogen). To make it easy to test against the latest source there is an MSVC project to compile the libhydrogen source code. See the [README](tests/README.md) for details.

## Feedback

Feedback, suggestions, and pull requests are welcome, thanks!