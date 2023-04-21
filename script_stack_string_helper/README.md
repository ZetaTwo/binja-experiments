# Script: Obfuscated Stack String Helper

A function which can help to deobfuscate simple obfuscated stack strings.

## Output

If you have a piece of code that looks like this:
```
00525d71      __builtin_strncpy(var_50c, "ewntfgw&lrn", 0xc);
...
00525e14      do
00525e14      {
00525e0c          &var_50c[edx_9] = ((1 + edx_9) ^ &var_50c[edx_9]);
00525e10          edx_9 = (edx_9 + 1);
00525e10      } while (edx_9 < 0xb);
```

You can call the helper function to deobfuscate the string:

```
> bytes(stackstring_helper(bv, 0x525e14, 'var_50c', 0xb, lambda i,x: x^(1+i)))
b'\x00umpcap.exe'
```

Note that the first byte is missing because Binja can't determine its value for some reason. However, it still produces useful results.
