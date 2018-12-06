<p align="center">
<img src="http://stoq.punchcyber.com/i/stoq.png" width="300"><br />
</p>

[![Documentation Status](https://readthedocs.org/projects/stoq-framework/badge/?version=v2)](https://stoq-framework.readthedocs.io/en/v2/)
[![License](https://img.shields.io/pypi/l/stoq-framework.svg)](https://pypi.org/project/stoq-framework/)

# Overview

stoQ is a automation framework that helps to simplify the mundane and repetitive
tasks an analyst is required to do. It allows analysts and DevSecOps teams the
ability to quickly transition between different data sources, databases,
decoders/encoders, and numerous other tasks using enriched and consistent data
structures. stoQ was designed to be enterprise ready and scalable, while also being
lean enough for individual security researchers.

# Documentation

If you're interested in learning more about stoQ, to include how to develop your
own plugins, checkout the [full documentation](https://stoq-framework.readthedocs.io/).

This git repository contains publicly available plugins that have been created
for use with stoQ. The core stoQ repository can be found [here](https://github.com/PUNCH-Cyber/stoq).

# Installation

Details on how to install these plugins can be found [here](https://stoq-framework.readthedocs.io/en/latest/installation.html#installing-plugins).

# Plugin List

Below is a listing of all public stoQ plugins, a description, and thier respective plugin class.

| Plugin Name  | Type                                                         | Description                        |
| ------------ | ------------------------------------------------------------ | ---------------------------------- |
| xdpcarve     | Carve and decode streams from XDP documents                  | Worker                             |
| stdout       | Sends results to STDOUT                                      | Connector                          |
| rtf          | Extract objects from RTF payloads                            | Worker                             |
| hash         | Hash content                                                 | Worker                             |
| dirmon       | Monitor a directory for newly created files for processing   | Provider                           |
| vtmis-search | Search VTMIS API                                             | Worker, Dispatcher, DeepDispatcher |
| peinfo       | Gather relevant information about an executable using pefile | Worker                             |
| javaclass    | Decodes and extracts information from Java Class files       | Worker                             |
| filedir      | Ingest a file or directory for processing                    | Provider, Connector, Archiver      |
| yarascan     | Process a payload using yara                                 | Worker, Dispatcher                 |
| decompress   | Extract content from a multitude of archive formats          | Worker                             |
| ole          | Carve OLE streams within Microsoft Office Documents          | Worker                             |
| iocextract   | Regex routines to extract and normalize IOC's from a payload | Worker                             |
| mraptor      | Port of mraptor3 from oletools                               | Worker                             |
| trid         | Identify file types from their TrID signature                | Worker                             |
| smtp         | SMTP Parser Worker                                           | Worker                             |
| exif         | Processes a payload using ExifTool                           | Worker                             |
| pecarve      | Carve portable executable files from a data stream           | Worker                             |
| swfcarve     | Carve and decompress SWF files from a data stream            | Worker                             |
