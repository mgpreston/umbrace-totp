# Umbrace.Totp

[![NuGet](https://img.shields.io/nuget/v/Umbrace.Totp.svg)](https://www.nuget.org/packages/Umbrace.Totp)
[![CI](https://github.com/mgpreston/umbrace-totp/actions/workflows/ci.yml/badge.svg)](https://github.com/mgpreston/umbrace-totp/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/mgpreston/umbrace-totp/graph/badge.svg?token=JMOAQI1DSO)](https://codecov.io/github/mgpreston/umbrace-totp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovateapp.com/)

An [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) compliant, low-allocation TOTP library for .NET 10+.

## Features

- RFC 6238 compliant TOTP generation and validation
- RFC 4226 compliant HOTP core
- SHA-1, SHA-256, and SHA-512 algorithm support
- Configurable digit count (6–8) and time step
- Validation window for clock drift tolerance
- Replay protection via `TimeStepMatched` in `ValidationResult`
- `otpauth://` URI construction and parsing ([Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))
- Zero-allocation validation and span-based code generation
- `TimeProvider` abstraction for testability
- Cryptographically secure key generation

## Installation

```shell
dotnet add package Umbrace.Totp
```

## Usage

### Generate a key

```csharp
byte[] secret = TotpKeyGenerator.GenerateKey();                          // 20 bytes (SHA-1)
byte[] secret256 = TotpKeyGenerator.GenerateKey(OtpAlgorithm.Sha256);   // 32 bytes
byte[] secret512 = TotpKeyGenerator.GenerateKey(OtpAlgorithm.Sha512);   // 64 bytes
```

### Generate a code

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

### Validate a code

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

### Configuration

```csharp
var options = new TotpOptions
{
    Algorithm = OtpAlgorithm.Sha256,
    Digits = 8,
    TimeStep = 60,
};
var generator = new TotpGenerator(options);
```

### otpauth:// URI (for QR codes)

```csharp
// Build a URI for an authenticator app
var uri = new TotpUri("alice@example.com", secret, issuer: "My App");
string qrContent = uri.ToString();
// otpauth://totp/My%20App:alice%40example.com?secret=...&issuer=My%20App

// Parse a URI
TotpUri parsed = TotpUri.Parse(qrContent);
TotpOptions options = parsed.ToTotpOptions();
```

### Testability

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

## License

MIT — see [LICENSE](LICENSE).