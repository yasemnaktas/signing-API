# Signing case — starter project

A minimal JVM project for the Cleverbase Integration & Support Engineer case, so you can spend your
time on the case instead of on project setup. Using it is optional: if you prefer another language or
build tool, go ahead.

## What's in it

- Java 17, Maven (via the included wrapper, so you only need a JDK).
- [Jackson](https://github.com/FasterXML/jackson-databind) for JSON. For HTTP, the JDK's built-in
  `java.net.http.HttpClient` is enough; for certificates and signatures, `java.security`.
- JUnit 5, with two small tests that check the setup works.
- `Main.java` with a `println`. Everything else is up to you.

## Getting started

Requires JDK 17 or newer.

```bash
./mvnw test                  # run the tests
./mvnw compile exec:java     # run Main
```

On Windows, use `mvnw.cmd`. The first run downloads Maven and the dependencies.

Please run `git init` and commit this starter as your first commit, so we can see what you added on top of it.

## Credentials

You receive test credentials for the service stub together with the case. Keep them out of git: read them
from environment variables or a local config file that is listed in `.gitignore`.

## Your README

Replace this file with your own README, as described in the case: how to run it and configure the
credentials, your design choices, what doesn't work yet, and which sources and tools (including AI) you used.
