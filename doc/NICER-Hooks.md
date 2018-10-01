NICER Hooks
===============
Philipps-University of Marburg, November 2017

Introduction
------------

Rhizome is a distributed Content Storage on top of the Serval Mesh Network, that implements opportunistic distribution of files.

The NICER Hooks are a way to hook external programs to three different parts of the Rhizome sync cycle: *Download*, *Content* and *Announce*. The exit status of the hooked programs is meant to influence the further processing of the Rhizome File inside of serval, e.g. not to download or not to propagate a file.

When a Hook is executed, Serval waits for the termination of the called program. The hooked programs therefore *should* terminate as fast as possible. Also, as the serval daemon execution is paused, no interaction will be possible, with neither the restful, nor the command line interface.

Hooks
--------------

### Download Hook

A Download Hook is executed whenever a new Rhizome Mainfest becomes present for the local serval instance.

The download hook is executed even before the actual file is downloaded an thus can be used to reject Rhizome files based upon their metadata.

Note: Currently the download hook is called when a manifest is seen the first time. If a bundle is rejected, there will be no second chance to accept it.

<!--TODO: Timeout for next filter execution-->

### Content Hook

A Content Hook is executed whenever a new Rhizome File and Manifest is about to be inserted into the local Rhizome Store, but before it is announced to other clients. Before the execution of this Hook the regarding file is exported to Servals temporary folder and thereby provided to the hooked program.

Content Hooks are intended to do in-depth analysis of the provided files, e.g. run face detection algorithms.

As those complex algorithms can take quite some time, it is suggested to:

1. fork the actual processing job
2. set the file inactive using the exit status (to avoid sharing the outdated file)
3. set the file active after the job finished, using the command-line or the RESTful interface __OR__ add the new derivate. 

### Announce Hook

An Announce Hook is executed whenever a Rhizome Bundle is announced to another client. As this will happen very often (default: 0.5 sec.) announce hooks can use quite an amount of resources.

The Announce Hooks are intended to announce files based upon local metadata e.g. the current time, battery state, ...

<!--TODO: SID of opponent-->

Configuration
--------------

As there are download, content and announce hooks, they are configured independently. One has to specify the full path of the executable / script:

```
rhizome.download_hook=/home/serval/download.sh
rhizome.content_hook=/home/serval/content.sh
rhizome.announce_hook=/home/serval/announce.sh
```

If no program path is defined the filter will be skipped.


Calling convention
--------------

When a hook program is executed, the **first argument** is the **manifest** in its text representation.

The second argument is optional (only set for content hooks) and provides the path to the decrypted file.

Therefore the calling convention can be described this way: `script.py [manifest] <filepath>`


Example for a provided manifest (in first argument):

```
name=LICENSE
service=file
version=1512029476796
...
```

To parse the manifest a rather simple python script can be used:

```python
#!/usr/bin/env python
import sys

attribs = {}
for pair in sys.argv[1].split("\n"):
    key, value = pair.split("=")
    attribs[key] = value
```
