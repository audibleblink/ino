# In 'n Out

Parse and return PE information

```json
ino -v comsvcs.dll

{
  "Name": "<string>",
  "Path": "<string>",
  "Type": "<string file|directory>",
  "Imphash": "<string>",
  "Imports": [{ 
  	"Host": "<string>", 
	"Functions": ["<string>",]},],
  "Exports": ["<string>",],
  "Forwards": ["<string>",],
  "PDB": "<string>",
  "Sections": [{
  	"Name": "<string>",
	"Perm": "<string>",
	"FileOffset": int,
	"VMA": int, 
	"Size": int,
  }],
}

```

If compiled as a Windows EXE, there will be an additional property:

```json
"DACL": {
      "Owner": "<string>",
      "Group": "<string>",
      "Aces": {
            "Principal": "<string>",
            "Rights": ["<string>", ...]
      }
}
```


```
Usage of ino:
  -def string
        Print a .def file for a mathing dll
        Ex: ino -def dbghelp.dll teams.exe
  -dir string
        Directory to recurse
  -exports
        Print Exports only
  -forwards
        Print Forwards only
  -imphash
        Print ImpHash only
  -imports
        Print Imports only
  -type string
        Use with --dir. Get [exe|dll]
  -v    Print additional fields
```

### Cypher / Neo4j

### Creating the Dataset

```bash
ino -dir /windows/system32 -type dll > sys32.dll.json
ino -dir /windows/system32 -type exe > sys32.exe.json
```

### Importing the Dataset to Neo4j

> the below queries are for an old version of the JSON output. they remain as notes for me to reference

```cypher
CALL apoc.load.json("file:///sys32_dll.json") 
YIELD value AS dllData
MERGE (dll:DLL {name: dllData.Name, complete: false})
SET dll.exports = dllData.Exports
SET dll.path = dllData.Path
SET dll.imphash = dllData.ImpHash
SET dll.complete =  true

WITH dll, dllData UNWIND dllData.Imports AS import
MERGE (dll1:DLL {name: import.Host})
FOREACH (i in CASE WHEN dll1.complete THEN [] ELSE [1] END |
	SET dll1.complete = false)
WITH dll, dll1, import, dllData UNWIND import.Functions as func
MERGE (dll)-[:IMPORTS {fn: func}]->(dll1)

WITH dll, dllData UNWIND dllData.Forwards AS fwd
MERGE (dll3:DLL {name: fwd.Host})
FOREACH (i in CASE WHEN dll3.complete THEN [] ELSE [1] END |
	SET dll3.complete = false)
WITH dll, dll3, fwd UNWIND fwd.Functions as func
MERGE (dll)-[:FORWARDS {fn: func}]->(dll3)
```

```cypher
CALL apoc.load.json("file:///sys32_exe.json")
YIELD value AS exeData
MERGE (exe:EXE {name: exeData.Name, path: exeData.Path, imphash: exeData.ImpHash})
SET exe.exports = exeData.Exports

WITH exe, exeData UNWIND exeData.Imports AS import
MERGE (dll:DLL {name: import.Host})
FOREACH (i in CASE WHEN dll.complete THEN [] ELSE [1] END |
	SET dll.complete = false)
WITH dll, exe, import, exeData UNWIND import.Functions as func
MERGE (exe)-[:IMPORTS {fn: func}]->(dll)

WITH exe, exeData UNWIND exeData.Forwards AS fwd
MERGE (dll2:DLL {name: fwd.Host})
FOREACH (i in CASE WHEN dll2.complete THEN [] ELSE [1] END |
	SET dll2.complete = false)
WITH dll2, exe, fwd UNWIND fwd.Functions as func
MERGE (exe)-[:FORWARDS {fn: func}]->(dll2)
```
