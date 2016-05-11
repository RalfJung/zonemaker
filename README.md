# zonemaker: Python DNS zone files

## Introduction

This is [zonemaker](https://www.ralfj.de/projects/zonemaker), a tool
to generate DNS zone files from Python.

The plain zone file format is pretty limited. There are not even
variables, so in many cases IP addresses and other data has to be
repeated several times.  zonemaker is an attempt to provide more
flexibility, by allowing you to write your zones in Python. Hence all
the usuel fatures, like variables, macros (also known as functions)
and loops, are available to generate DNS zone data. At the same time,
zonemaker is reasonably simple and close to the actual structure of a
DNS zonefile, so it is suited for small setups. The output of
zonemaker is a standard zonefile, it can be used with any DNS server
supporting those.

## Usage

Simply call `zonemaker` with the zone python file as argument. The
result will be printed to stdout. See `db.example.com.py` for a sample
file demonstrating the use of the interface. `Makefile.sample` shows
how a makefile which first updates the zone(s), and then tells BIND to
reload, could look like.

## Source, License

You can find the sources in the
[git repository](https://git.ralfj.de/zonemaker.git) (also
available [on GitHub](https://github.com/RalfJung/zonemaker)).  They
are provided under a
[2-clause BSD license](http://opensource.org/licenses/bsd-license.php). See
the file `LICENSE-BSD` for more details.

## Contact

If you found a bug, or want to leave a comment, please
[send me a mail](mailto:post-AT-ralfj-DOT-de).
