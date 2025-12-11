# AAPatch
A multi-file patch format.
Handles files hashing, conditional patching and different alias per input file.

## Minimal example

Let's say you have two folders:

 - "ori" contains the original files you want to patch;
 - "new" contains the patched files.

You can do the following to create a patch...

```python
import aapatch
aap = aapatch.new()
aap.load_origin('ori')
aap.load_destination('new')
aap.write('patch.aapatch')
```
...and apply it inplace like that:

```python
import aapatch
aap = aapatch.load('patch.aapatch')
aap.patch('ori')
```
The files inside the ori folder should now be identical to those in the new folder.