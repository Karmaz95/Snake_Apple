# Snake_Apple
The code repository for the Snake&amp;Apple article series.

## ARTICLES
![alt](img/Snake_Apple.jpg)
* &#9745; [I. Mach-O](https://medium.com/p/a8eda4b87263)
* &#9744; [II. Code Signing]()
* &#9744; [III. Checksec]()
* &#9744; [IV. Dylibs]()

## TOOLS
![alt](img/CrimsonUroboros.jpg)
[CrimsonUroboros](I.%20Mach-O/python/CrimsonUroboros.py) - core program resulting from the Snake&Apple article series for binary analysis. You may find older versions of this script in each article directory in this repository.
* Usage
```console
usage: CrimsonUroboros.py [-h] -p PATH [--file_type] [--header_flags] [--endian] [--header] [--load_commands] [--segments] [--sections] [--symbols] [--chained_fixups] [--exports_trie]
                          [--uuid] [--main] [--strings_section] [--all_strings] [--save_strings SAVE_STRINGS] [--info]

Mach-O files parser for binary analysis.

options:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to the Mach-O file.
  --file_type           Print binary file type.
  --header_flags        Print binary header flags.
  --endian              Print binary endianess.
  --header              Print binary header.
  --load_commands       Print binary load commands names.
  --segments            Print binary segments in human friendly form.
  --sections            Print binary sections in human friendly form.
  --symbols             Print all binary symbols.
  --chained_fixups      Print Chained Fixups information.
  --exports_trie        Print Export Trie information.
  --uuid                Print UUID.
  --main                Print entry point and stack size.
  --strings_section     Print strings from __cstring section.
  --all_strings         Print strings from all sections.
  --save_strings SAVE_STRINGS
                        Parse all sections, detect strings and save them to a file.
  --info                Print header, load commands, segments, sections, symbols and strings.
```
* Example:
```bash
CrimsonUroboros.py -p PATH --info
```
[MachOFileFinder](I.%20Mach-O/python/MachOFileFinder.py) - designed to find ARM64 Mach-O binaries within a specified directory and print their file type.
* Usage:
```bash
python MachOFileFinder.py PATH
```
* Example:
```bash
python MachOFileFinder.py . -r 2>/dev/null
EXECUTE:/Users/karmaz95/t/pingsender
DYLIB:/Users/karmaz95/t/dylibs/use_dylib_app/customs/custom.dylib
BUNDLE:/Users/karmaz95/t/bundles/MyBundle
```

## WHY UROBOROS? 
I will write the code for each article as a class SnakeX, where X will be the article number. To make it easier for the audience to follow. Each Snake class will be a child of the previous one and infinitely "eat itself" (inherit methods of the previous class), like Uroboros.
