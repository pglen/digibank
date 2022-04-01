# DigiBank

## Foundational routines for digital banking

No usable high level stuff, however a ton of infrastructure level 'C' code

Dir Map:

Directory | Description | Notes
------------|------------------|------
diba        | Old 'C' code     | This is where the useful routines are
diba/tools  | 'C' code tools   | This is where the useful routines are
libgcrypt   | frozen           | at the time of project start (secure)
sqlite      | frozen           | at the time of project start (checksummed)

Notables:

    zmalloc     provides a tagged malloc without any system dependencies
    base64      exactly what you would expect
    cmdline     parse command line (without external libs)
    dibafile    write / retrieve chunks of info
    zstr        concat multiple strings back to back to target

    This is just a sampler ... use the source -Luke-


