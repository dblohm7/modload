#!/bin/bash
cl -MT -EHsc -Zi -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN modload.cpp -link -manifestinput:modload.exe.manifest -manifest:embed
