# RadonFuscator
This is a protector for native binaries.

## How does it work?
It encrypts all PE segments excluding .rsrc and .reloc of course and then adds a stub to a new section and sets the entrypoint there.
Then on runtime the stub decrypts the sections and jumps to OEP. It also has some simple anti dump and anti debug tricks which could be improved.

## Donating
BTC: bc1qclp38ttjy3nad0r5ca2skkjtyrma7ssg2ctady

ETH: 0x1DC20DB2985b14cA483071c29dC0eDdCbF100019

LTC: LTtv4qaKDXUaqFjzzBFDLhYUiMTHQtV1Rc

## Disclaimer
This protector will not work if the executable uses TLS callbacks but support for them can be added.
Based on: http://www.codereversing.com/blog/archives/95
