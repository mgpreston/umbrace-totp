# Contributing

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)

## Build

```shell
dotnet build
```

## Test

```shell
dotnet test
```

To collect coverage:

```shell
dotnet test -- --coverage --coverage-output-format cobertura --coverage-output coverage.xml
```

## Benchmarks

```shell
dotnet run --project benchmarks/Umbrace.Totp.Benchmarks --configuration Release
```

## Code style

This repository uses `.editorconfig` to enforce formatting. CI will fail on any unformatted code. Run the following before pushing to catch issues locally:

```shell
dotnet format
```

## Pull requests

- Keep changes focused; one concern per PR.
- All tests must pass and coverage must remain at 100%.
- New public API requires XML documentation.

## Reporting issues

Open an issue on [GitHub](https://github.com/mgpreston/umbrace-totp/issues). For security vulnerabilities, see [SECURITY.md](SECURITY.md).