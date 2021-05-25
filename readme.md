# In 'n Out

Parses PEs and spits out Imports and Exports

```
ino -v comsvcs.dll

{
  "Name": "comsvcs.dll",
  "Imports": [...],
  "Exports": [...],
  "Forwards": [...],
  "PDB": "",
  "FileHeader": [...],
  "Sections": [...],
}

```


```
Usage of ino:
  -exports
        Print Exports only
  -imports
        Print Imports only
  -imphash
        Print ImpHash only
  -v
        Print additional fields
  <pe_file>
        Required: Path to PE File
```
