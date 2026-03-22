# Umbrace.Totp

[![NuGet](https://img.shields.io/nuget/v/Umbrace.Totp.svg)](https://www.nuget.org/packages/Umbrace.Totp)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![AOT Compatible](https://img.shields.io/badge/AOT-compatible-512BD4)](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)
[![CI](https://github.com/mgpreston/umbrace-totp/actions/workflows/ci.yml/badge.svg)](https://github.com/mgpreston/umbrace-totp/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/mgpreston/umbrace-totp/graph/badge.svg?token=JMOAQI1DSO)](https://codecov.io/github/mgpreston/umbrace-totp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovateapp.com/)

An [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) / [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) compliant, low-allocation TOTP and HOTP library for .NET 10+.

## Features

- RFC 6238 compliant TOTP generation and validation
- RFC 4226 compliant HOTP generation and validation
- SHA-1, SHA-256, and SHA-512 algorithm support
- Configurable digit count (6–8), time step (TOTP), and lookahead window (HOTP)
- TOTP validation window for clock drift tolerance
- Replay protection via `TimeStepMatched` (TOTP) and `NextCounter` (HOTP)
- `otpauth://` URI construction and parsing for both `totp` and `hotp` types ([Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))
- Zero-allocation validation and span-based code generation
- Trim-safe and Native AOT compatible
- `TimeProvider` abstraction for testability
- Cryptographically secure key generation and HKDF key derivation ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869))

## Installation

```shell
dotnet add package Umbrace.Totp
```

## Usage

### Generate a key

Key generation is shared between TOTP and HOTP:

```csharp
byte[] secret = TotpKeyGenerator.GenerateKey();                          // 20 bytes (SHA-1)
byte[] secret256 = TotpKeyGenerator.GenerateKey(OtpAlgorithm.Sha256);   // 32 bytes
byte[] secret512 = TotpKeyGenerator.GenerateKey(OtpAlgorithm.Sha512);   // 64 bytes
```

For zero-allocation scenarios — write directly into a caller-provided buffer:

```csharp
Span<byte> key = stackalloc byte[TotpKeyGenerator.RecommendedKeyLength(OtpAlgorithm.Sha1)];
TotpKeyGenerator.TryGenerateKey(key);

// With an explicit algorithm
Span<byte> key256 = stackalloc byte[TotpKeyGenerator.RecommendedKeyLength(OtpAlgorithm.Sha256)];
TotpKeyGenerator.TryGenerateKey(key256, OtpAlgorithm.Sha256);
```

#### Derive a key from a master secret

For server-side deployments where storing a per-user secret is undesirable, derive
secrets deterministically from a single master key and a per-user context:

```csharp
// Store this once; keep it secret
byte[] masterKey = TotpKeyGenerator.GenerateKey();

// Derive a per-user secret on demand — no per-user storage needed
byte[] userSecret = TotpKeyGenerator.DeriveKey(masterKey, "user@example.com"u8);
```

For zero-allocation scenarios:

```csharp
Span<byte> destination = stackalloc byte[TotpKeyGenerator.RecommendedKeyLength(OtpAlgorithm.Sha1)];
TotpKeyGenerator.TryDeriveKey(masterKey, "user@example.com"u8, destination);
```

The same master key and context always produce the same secret. The context should
uniquely identify the user or account (e.g. a user ID or email address encoded as UTF-8).

---

### TOTP

#### Generate a code

```csharp
var generator = new TotpGenerator();

GenerationResult result = generator.GenerateCode(secret);
Console.WriteLine(result.Code);          // e.g. "123456"
Console.WriteLine(result.StepStartedAt); // when the current step began
Console.WriteLine(result.ExpiresAt);     // when the code expires
```

For zero-allocation scenarios (e.g. writing directly to an HTTP response):

```csharp
Span<char> buffer = stackalloc char[6];
if (generator.TryGenerateCode(secret, buffer, out int charsWritten))
{
    // use buffer[..charsWritten]
}

// UTF-8 variant
Span<byte> utf8Buffer = stackalloc byte[6];
if (generator.TryGenerateCodeUtf8(secret, utf8Buffer, out int bytesWritten))
{
    // use utf8Buffer[..bytesWritten]
}
```

#### Validate a code

```csharp
ValidationResult result = generator.ValidateCode(secret, userInput);

if (result)
{
    // Code is valid. Use result.TimeStepMatched for replay protection —
    // reject any future code with the same TimeStepMatched value.
}
```

With a validation window to tolerate clock drift:

```csharp
var window = new ValidationWindow(lookBehind: 1, lookAhead: 1);
ValidationResult result = generator.ValidateCode(secret, userInput, window);
```

#### Configuration

```csharp
var options = new TotpOptions
{
    Algorithm = OtpAlgorithm.Sha256,
    Digits = 8,
    TimeStep = 60,
};
var generator = new TotpGenerator(options);
```

#### otpauth:// URI (for QR codes)

```csharp
// Build a URI for an authenticator app
var uri = new TotpUri("alice@example.com", secret, issuer: "My App");
string qrContent = uri.ToString();
// otpauth://totp/My%20App:alice%40example.com?secret=...&issuer=My%20App

// Parse a URI
TotpUri parsed = TotpUri.Parse(qrContent);
TotpOptions options = parsed.ToTotpOptions();
```

#### Testability

`TotpGenerator` accepts a `TimeProvider`, making it straightforward to test time-sensitive behaviour:

```csharp
var timeProvider = new FakeTimeProvider();
var generator = new TotpGenerator(timeProvider: timeProvider);

timeProvider.SetUtcNow(DateTimeOffset.UtcNow);
string code = generator.GenerateCode(secret).Code;

// Advance time and verify the code is no longer valid
timeProvider.Advance(TimeSpan.FromSeconds(31));
Assert.False(generator.ValidateCode(secret, code));
```

`FakeTimeProvider` is available from the [`Microsoft.Extensions.TimeProvider.Testing`](https://www.nuget.org/packages/Microsoft.Extensions.TimeProvider.Testing) package.

---

### HOTP

HOTP is counter-based. The caller is responsible for persisting the counter and advancing
it after each successful validation.

#### Generate a code

```csharp
var generator = new HotpGenerator();

string code = generator.GenerateCode(secret, counter: storedCounter);
```

For zero-allocation scenarios:

```csharp
Span<char> buffer = stackalloc char[6];
if (generator.TryGenerateCode(secret, storedCounter, buffer, out int charsWritten))
{
    // use buffer[..charsWritten]
}

// UTF-8 variant
Span<byte> utf8Buffer = stackalloc byte[6];
if (generator.TryGenerateCodeUtf8(secret, storedCounter, utf8Buffer, out int bytesWritten))
{
    // use utf8Buffer[..bytesWritten]
}
```

#### Validate a code

After a successful validation, **you must advance the counter** before persisting it.
`NextCounter` gives the value to store:

```csharp
HotpValidationResult result = generator.ValidateCode(secret, userInput, storedCounter);

if (result)
{
    storedCounter = result.NextCounter; // persist this before the next call
}
```

To accommodate counter desynchronisation (e.g. the user generated several codes without
validating them), pass a lookahead window. RFC 4226 §7.4 recommends a value of 5:

```csharp
HotpValidationResult result = generator.ValidateCode(secret, userInput, storedCounter,
    lookahead: HotpGenerator.DefaultLookahead);

if (result)
{
    storedCounter = result.NextCounter;
}
```

#### Configuration

```csharp
var options = new HotpOptions
{
    Algorithm = OtpAlgorithm.Sha256,
    Digits = 8,
};
var generator = new HotpGenerator(options);
```

#### otpauth:// URI (for QR codes)

```csharp
// Build a URI for an authenticator app
var uri = new HotpUri("alice@example.com", secret, counter: storedCounter, issuer: "My App");
string qrContent = uri.ToString();
// otpauth://hotp/My%20App:alice%40example.com?secret=...&issuer=My%20App&counter=0

// Parse a URI
HotpUri parsed = HotpUri.Parse(qrContent);
HotpOptions options = parsed.ToHotpOptions();
long initialCounter = parsed.Counter;
```

## License

MIT — see [LICENSE](LICENSE).
