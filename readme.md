# In 'n Out

Parses PEs and spits out Imports and Exports

```
ino comsvcs.dll

{
  "Name": "comsvcs.dll",
  "Imports": [...],
  "Exports": [...],
  "Forwards": [...]

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
  <pe_file>
        Required: Path to PE File
```
