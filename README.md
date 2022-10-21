# Hooks x86/x64

+ THE HOOKS WORK CORRECTLY ONLY IN RELEASE MODE
+ Compiler - msvc 14
+ Optimization Flags - /Oi /O2
+ CC - _cdecl / __stdcall work both

# Hook32
```asm
jmp relative_address 
```
  + Minimum bytes needed for hook32 is 5

# Hook64
```asm
push rax
mov  rax, absolute_address
jmp  rax
; junk
pop  rax ; at the end of the safe space
```
  + Minimum bytes needed for hook64 is 14
  + There is a rax recovery code, there may be problems

# How to use

```C
bool Set (
    PBYTE functionToHook, 
    PBYTE newFunction, 
    DWORD countOfSafeByte)
```
1. `PBYTE functionToHook` - ptr to function you want to hook
2. `PBYTE newFunction` - ptr to function you want to use instead
3. `DWORD countOfSafeByte` - the number of safe bytes to write the jmp instruction and safely use the original function 

For example you have function like this `[x86]`
```
int __stdcall PrintArgs(int argc, char** argv)
    000A1320 55                   push        ebp
    000A1321 8B EC                mov         ebp,esp
    000A1323 83 E4 F8             and         esp,0FFFFFFF8h
```
In Hook32, you need 5 bytes for the jmp instruction, but if you want to use the original function in the Hooked version, you need to pass 6 (in other function it may be bigger), because if you pass 5, the original instructions will be destroyed.
It works this way because of the rewriting of the original instructions. 

View after set hook32:
```
int __stdcall PrintArgs(int argc, char** argv)
    000A1320 E9 AB CD EF FF       jmp   0xABCDEDFF  ; jmp to our Hook function
    000A1325 F8                   ??    ?? ?? ?? ?? ; ruined
```

Call original function. In our buffer it looks like:
```
our buffer:
    ; original instructions
    000F1320 55                   push   ebp
    000F1321 8B EC                mov    ebp,esp
    000F1323 83 E4 F8             and    esp,0FFFFFFF8h
    ; jmp to original PrintArgs+6 function
    000F1326 E9 00 0A 13 26       jmp    0x000A1326
```