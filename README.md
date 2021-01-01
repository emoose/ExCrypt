# ExCrypt

ExCrypt is an open-source drop-in replacement for the XeCrypt suite of functions used by the Xbox 360.

It's been designed to be as closely compatible to those functions as possible - perhaps at the expense of various security & performance concerns.

As such, it should only be used where compatibility with existing Xbox 360 code/data is required. 

### Contents

The goal of ExCrypt is to implement XeCrypt functions known to be used on the Xbox 360.

We only target XeCrypt functions that are exported from the kernel, used during X360 boot, or included inside a game/app.

For a list of XeCrypt targets, their status, and any implementation-specific notes, take a look at the [implementation status page](https://github.com/emoose/ExCrypt/issues/5).

### Implementation

Code has to make sure to set the exact same state variables & return values as the 360 functions do.

This doesn't mean variables local to the function have to match up though - only data that is somehow written externally (hence could maybe be acted on by other non-XeCrypt code) should be kept exact, the rest can work however we want.

Code is expected to be receiving big-endian data, converting that data to little-endian to be worked on may be required.

Some effort to make the code a bit more readable, rather than just a straight assembly-to-C conversion, would be appreciated (though isn't exactly mandatory, so long as the code actually works)

We only target x86 & x64 - maybe other platforms in the future, but for now there's not much use in supporting anything else.

Where possible, making use of existing, well-known crypto code is always preferrable to needing to write your own (unless some XeCrypt oddity somehow prevents it, that is)
