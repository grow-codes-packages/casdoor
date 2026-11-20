# Java examples

Install the package into your local Maven repository, point it at a running Casdoor and run an
example:

```bash
make -C ../../java pack            # builds and installs codes.grow.packages:casdoor
export GROW_CASDOOR_URL=http://127.0.0.1:8000
export GROW_CASDOOR_TOKEN=...   # when the service needs one
mvn -q compile exec:java                                                  # BasicExample
mvn -q compile exec:java -Dexec.mainClass=codes.grow.packages.casdoor.examples.AsyncExample
```

Against the published package, set `-Dsdk.version=<version>` (or edit `pom.xml`) instead of
installing it locally.

| Class | Shows |
| - | - |
| `BasicExample` | blocking client: health, ping, server version, error handling |
| `AsyncExample` | `…Async` methods, combining futures, cancellation |
| `HooksAndLoggingExample` | request hooks, a logger, retries and timeouts |
