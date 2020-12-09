Gemini Client/Server
====================
An implementation of the [Gemini protocol](https://gemini.circumlunar.space/).
Provides both a client and server.

**STATUS:**  This is an experimental, very naive implementation. Use at your
own risk!

Requirements
------------
This project requires the following software to build:

  * C compiler
  * make
  * OpenSSL >= 1.1.0
  * uriparser
  * libmagic

Build
-----
Build both the client and server with:

    $ make all

Alternately, build only the client or server with `make glv` or `make agena`,
respectively.

Installation
------------
Run the following command to build and install the client and server (as root
if necessary):

    $ make clean install

Use
---
### Client

    glv URL

Fetch and display `URL` using the gemini protocol. Gemini files are displayed
with appropriate formatting and semantics, other files are rendered as plain
text.

### Server

    agena [OPTIONS...] [ROOT_PATH]

Serve the contents of ROOT_PATH (defaults to current directory) using the gemini
protocol. The default port is 1965.

License and Copyright
---------------------
Copyright (C) 2020 Corey Hinshaw

Licensed under the terms of the MIT license. See the LICENSE file for details.

Portions of the source code are licensed under the Academic Free License
version 2.0 and are:

Copyright (C) 2003  Red Hat, Inc.
Copyright (C) 2003  Jonathan Blandford <jrb@alum.mit.edu>

