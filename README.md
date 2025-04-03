# Penetration-Testing-Tools
Python tools for penetration testers
====================================

If you are involved in vulnerability research, reverse engineering or
pentesting, I suggest to try out the
[Python](http://www.python.org) programming language. It has a rich set
of useful libraries and programs. This page lists some of them.

Most of the listed tools are written in Python, others are just Python
bindings for existing C libraries, i.e. they make those libraries easily
usable from Python programs.

Some of the more aggressive tools (pentest frameworks, bluetooth
smashers, web application vulnerability scanners, war-dialers, etc.) are
left out, because the legal situation of these tools is still a bit
unclear in Germany -- even after the [decision of the highest
court](http://www.bundesverfassungsgericht.de/entscheidungen/rk20090518_2bvr223307.html).
This list is clearly meant to help whitehats, and for now I prefer to
err on the safe side.

### Network

-   [Scapy](https://scapy.net): send, sniff and dissect
    and forge network packets. Usable interactively or as a library
-   [Impacket](http://oss.coresecurity.com/projects/impacket.html):
    craft and decode network packets. Includes support for higher-level
    protocols such as NMB and SMB
-   [SMBMap](https://github.com/ShawnDEvans/smbmap): 
    enumerate Samba share drives across an entire domain
-   [dpkt](https://github.com/kbandla/dpkt): fast, simple packet
    creation/parsing, with definitions for the basic TCP/IP protocols
-   [AutoRecon](https://github.com/Tib3rius/AutoRecon): Multi-threaded network reconnaissance tool
-   [Mitm6](https://github.com/fox-it/mitm6): IPv6-based MITM tool that exploits IPv6 features to conduct man-in-the-middle attacks
-   [Habu](https://github.com/portantier/habu): 
    python network hacking toolkit
-   [Knock Subdomain Scan](https://github.com/guelfoweb/knock), enumerate
    subdomains on a target domain through a wordlist
-   [SubBrute](https://github.com/TheRook/subbrute), fast subdomain
    enumeration tool
-   [pypcap](https://github.com/dugsong/pypcap),
    [Pcapy](https://github.com/helpsystems/pcapy),
    [Pcapy-NG](https://github.com/stamparm/pcapy-ng) and
    [libpcap](https://pypi.org/project/libpcap/): several different
    Python bindings for libpcap
-   [libdnet](https://github.com/ofalk/libdnet/): low-level networking
    routines, including interface lookup and Ethernet frame transmission
-   [Mallory](https://github.com/intrepidusgroup/mallory), extensible
    TCP/UDP man-in-the-middle proxy, supports modifying non-standard
    protocols on the fly
-   [Pytbull-NG](https://github.com/netrunn3r/pytbull-ng/): flexible IDS/IPS testing
    framework (shipped with more than 300 tests)
-   [Spoodle](https://github.com/vjex/spoodle): A mass subdomain + poodle
    vulnerability scanner

### Debugging and reverse engineering

-   [Frida](http://www.frida.re/): A dynamic instrumentation framework which can
    inject scripts into running processes
-   [Capstone](http://www.capstone-engine.org/): lightweight
    multi-platform, multi-architecture disassembly framework with Python
    bindings
-   [Unicorn Engine](https://www.unicorn-engine.org/): CPU emulator framework with Python bindings
-   [Androguard](https://github.com/androguard/androguard): reverse
    engineering and analysis of Android applications
-   [Paimei](https://github.com/OpenRCE/paimei): reverse engineering
    framework, includes [PyDBG](https://github.com/OpenRCE/pydbg), PIDA,
    pGRAPH
-   [IDAPython](https://github.com/idapython/src): IDA Pro plugin that
    integrates the Python programming language, allowing scripts to run
    in IDA Pro
-   [PyEMU](hhttps://github.com/codypierce/pyemu/): fully scriptable IA-32
    emulator, useful for malware analysis
-   [pefile](https://github.com/erocarrera/pefile): read and work with
    Portable Executable (aka PE) files
-   [pydasm](https://github.com/jtpereyda/libdasm/tree/master/pydasm):
    Python interface to the [libdasm](https://github.com/jtpereyda/libdasm/tree/master/)
    x86 disassembling library
-   [PyDbgEng](http://pydbgeng.sourceforge.net/): Python wrapper for the
    Microsoft Windows Debugging Engine
-   [diStorm](https://github.com/gdabah/distorm): disassembler library
    for AMD64, licensed under the BSD license
-   [python-ptrace](http://python-ptrace.readthedocs.org/):
    debugger using ptrace (Linux, BSD and Darwin system call to trace
    processes) written in Python
-   [Keystone](http://www.keystone-engine.org): lightweight multi-platform,
    multi-architecture assembler framework with Python bindings
-   [PyBFD](https://github.com/Groundworkstech/pybfd/): Python interface
    to the GNU Binary File Descriptor (BFD) library
-   [CHIPSEC](https://github.com/chipsec/chipsec): framework for analyzing the
    security of PC platforms including hardware, system firmware (BIOS/UEFI),
    and platform components.
-   [Ghidatron](https://github.com/mandiant/Ghidrathon): The FLARE team's open-source extension to add Python 3 scripting to Ghidra.

### Fuzzing

-   [afl-python](http://jwilk.net/software/python-afl): enables American fuzzy
    lop fork server and instrumentation for pure-Python code
-   [Sulley](https://github.com/OpenRCE/sulley): fuzzer development and
    fuzz testing framework consisting of multiple extensible components
-   [Peach Fuzzing Platform](https://github.com/MozillaSecurity/peach/):
    extensible fuzzing framework for generation and mutation based
    fuzzing (v2 was written in Python)
-   [untidy](https://github.com/kbandla/python-untidy/): general purpose XML fuzzer
-   [Powerfuzzer](http://www.powerfuzzer.com/): highly automated and
    fully customizable web fuzzer (HTTP protocol based application
    fuzzer)
-   [Construct](http://construct.readthedocs.org/): library for parsing
    and building of data structures (binary or textual). Define your
    data structures in a declarative manner
-   [Fusil](http://fusil.readthedocs.org/): Python library
    used to write fuzzing programs

### Web

-   [XSStrike](https://github.com/s0md3v/XSStrike): Advanced XSS detection suite
-   [Requests](https://requests.readthedocs.io/): elegant and simple HTTP
    library, built for human beings
-   [lxml](http://lxml.de/index.html): easy-to-use library for processing XML and HTML; similar to Requests
-   [HTTPie](http://httpie.org): human-friendly cURL-like command line
    HTTP client
-   [Twill](https://twill-tools.github.io/twill/): browse the Web from a command-line
    interface. Supports automated Web testing
-   [FunkLoad](https://github.com/nuxeo/FunkLoad): functional and load web
    tester
-   [spynner](https://github.com/makinacorpus/spynner): Programmatic web
    browsing module for Python with Javascript/AJAX support
-   [mitmproxy](http://mitmproxy.org/): SSL-capable, intercepting HTTP
    proxy. Console interface allows traffic flows to be inspected and
    edited on the fly
-   [spidy](https://github.com/rivermont/spidy/): simple command-line web crawler with page downloading and word scraping
-   [https://github.com/TrixSec/waymap](Waymap): web vulnerability scanner built for penetration testers


### Forensics

-   [Volatility](http://www.volatilityfoundation.org/):
    extract digital artifacts from volatile memory (RAM) samples
-   [Rekall](https://github.com/google/rekall):
    memory analysis framework developed by Google
-   [TrIDLib](http://mark0.net/code-tridlib-e.html), identify file types
    from their binary signatures. Now includes Python binding

### Malware analysis

-   [pyew](https://github.com/joxeankoret/pyew): command line hexadecimal
    editor and disassembler, mainly to analyze malware
-   [Exefilter](https://github.com/decalage2/exefilter): filter file formats
    in e-mails, web pages or files. Detects many common file formats and
    can remove active content
-   [jsunpack-n](https://github.com/urule99/jsunpack-n), generic
    JavaScript unpacker: emulates browser functionality to detect
    exploits that target browser and browser plug-in vulnerabilities
-   [yara-python](https://github.com/VirusTotal/yara-python):
    identify and classify malware samples
-   [phoneyc](https://github.com/honeynet/phoneyc): pure Python
    honeyclient implementation
-   [CapTipper](https://github.com/omriher/CapTipper): analyse, explore and
    revive HTTP malicious traffic from PCAP file
-   [Cuckoo](https://github.com/cuckoosandbox/cuckoo): Automated malware analysis system
-   [CAPE](https://github.com/kevoreilly/CAPEv2): Malware configuration and payload extraction

### PDF

-   [pdfminer.six](https://github.com/pdfminer/pdfminer.six):
    extract text from PDF files
-   [peepdf-3](https://github.com/digitalsleuth/peepdf-3):
    Python tool to analyse and explore PDF files to find out if they can be harmful
-   [Didier Stevens' PDF
    tools](http://blog.didierstevens.com/programs/pdf-tools): analyse,
    identify and create PDF files
-   [pyPDF](https://pypdf.readthedocs.io/): pure Python PDF toolkit: extract
    info, spilt, merge, crop, encrypt, decrypt...

### Misc

-   [Angr](https://github.com/angr/angr): Powerful binary analysis framework for vulnerability research and exploit development
-   [ScoutSuite](https://github.com/nccgroup/ScoutSuite): Multi-cloud security auditing tool
-   [Exomind](https://github.com/jio-gl/exomind):
    framework for building decorated graphs and developing open-source
    intelligence modules and ideas, centered on social network services,
    search engines and instant messaging
-   [simplejson](https://github.com/simplejson/simplejson/): JSON
    encoder/decoder, e.g. to use [Google's AJAX
    API](http://dcortesi.com/2008/05/28/google-ajax-search-api-example-python-code/)
-   [PyMangle](http://code.google.com/p/pymangle/): command line tool
    and a python library used to create word lists for use with other
    penetration testing tools
-   [Hachoir](https://hachoir.readthedocs.io/en/latest/): view and
    edit a binary stream field by field 
-   [py-mangle](http://code.google.com/p/pymangle/): command line tool
    and a python library used to create word lists for use with other
    penetration testing tools
-   [wmiexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py):
    execute Powershell commands quickly and easily via WMI
-   [Pentestly](https://github.com/praetorian-inc/pentestly):
    Python and Powershell internal penetration testing framework
-   [hacklib](https://github.com/leonli96/python-hacklib):
    Toolkit for hacking enthusiasts: word mangling, password guessing,
    reverse shell and other simple tools
-   [Certipy](https://github.com/ly4k/Certipy): Active Directory Certificate Services enumeration and abuse tool
-   [BloodHound.py](https://github.com/fox-it/BloodHound.py): Python-based BloodHound ingestor for Active Directory security assessment


### Other useful libraries and tools

-   [Project Jupyter](https://jupyter.org): enhanced interactive 
    shell with many features for object introspection, system shell
    access, and its own special command system
-   [Beautiful Soup](http://www.crummy.com/software/BeautifulSoup/):
    HTML parser optimized for screen-scraping
-   [matplotlib](https://matplotlib.org): make 2D plots of
    arrays
-   [Mayavi](http://code.enthought.com/projects/mayavi/): 3D scientific
    data visualization and plotting
-   [RTGraph3D](http://www.secdev.org/projects/rtgraph3d/): create
    dynamic graphs in 3D
-   [Twisted](http://twistedmatrix.com/): event-driven networking engine
-   [Suds](https://github.com/suds-community/suds): lightweight SOAP client for
    consuming Web Services
-   [NetworkX](https://networkx.org): graph library (edges, nodes)
-   [Pandas](http://pandas.pydata.org/): library providing
    high-performance, easy-to-use data structures and data analysis
    tools
-   [pyparsing](https://pypi.org/project/pyparsing/): general parsing
    module
-   [lxml](http://lxml.de/): most feature-rich and easy-to-use library
    for working with XML and HTML in the Python language
-   [Whoosh](https://github.com/whoosh-community/whoosh): fast, featureful
    full-text indexing and searching library implemented in pure Python
-   [Pexpect](https://github.com/pexpect/pexpect): control and automate
    other programs, similar to Don Libes \`Expect\` system
-   [SikuliX](https://sikulix.github.io/docs/scripts/python/), visual technology
    to search and automate GUIs using screenshots. Scriptable in
-   [PyQt](http://www.riverbankcomputing.co.uk/software/pyqt) and
    [PySide](http://www.pyside.org/): Python bindings for the Qt
    application framework and GUI library

### Books

-   [Violent Python](https://www.elsevier.com/books/violent-python/unknown/978-1-59749-957-6) by TJ O'Connor. A Cookbook for Hackers, Forensic Analysts, Penetration Testers and Security Engineers
-   [Grey Hat Python](http://www.nostarch.com/ghpython.htm) by Justin Seitz: 
    Python Programming for Hackers and Reverse Engineers.
-   [Black Hat Python](http://www.nostarch.com/blackhatpython) by Justin Seitz:
    Python Programming for Hackers and Pentesters
-   [Python Penetration Testing Essentials](https://github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition) by Mohit:
    Employ the power of Python to get the best out of pentesting
-   [Python for Secret Agents](https://www.packtpub.com/en-us/product/python-for-secret-agents-volume-ii-9781785283406) by Steven F. Lott. Analyze, encrypt, and uncover intelligence data using Python
-   [Python Web Penetration Testing Cookbook](https://www.packtpub.com/en-us/product/python-web-penetration-testing-cookbook-9781784399900) by Cameron Buchanan et al.: Over 60 Python recipes for web application testing
-   [Learning Penetration Testing with Python](https://www.packtpub.com/en-us/product/learning-penetration-testing-with-python-9781785289552) by Christopher Duffy: Utilize Python scripting to execute effective and efficient penetration tests
-   [Python Forensics](http://www.sciencedirect.com/science/book/9780124186767) by Chet Hosmer:
    A Workbench for Inventing and Sharing Digital Forensic Technology
-   [The Beginner's Guide to IDAPython](https://leanpub.com/IDAPython-Book) by Alexander Hanel
-   [Python for Offensive PenTest: A Practical Guide to Ethical Hacking and Penetration Testing Using Python](https://www.amazon.com/Python-Offensive-PenTest-practical-penetration/dp/1788838971) by Hussam Khrais

### More stuff

-   [SecurityTube Python Scripting Expert (SPSE)](https://github.com/ioef/SPSE/) is an online course and certification offered by Vivek Ramachandran.
-   SANS offers the course [SEC573: Automating Information Security with Python](https://www.sans.org/cyber-security-courses/automating-information-security-with-python/).
-   There is a SANS paper about Python libraries helpful for forensic analysis
    [(PDF)](http://www.sans.org/reading_room/whitepapers/incident/grow-forensic-tools-taxonomy-python-libraries-helpful-forensic-analysis_33453).
-   For more Python libaries, please have a look at
    [PyPI](http://pypi.python.org/pypi), the Python Package Index.
