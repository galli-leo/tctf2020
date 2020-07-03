We are greeted with a binary file download and an initial investigation with file reveals a 32-bit ELF binary (stripped, of course):
```
➜ file happy_tree
happy_tree: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fd7f1b2d769e389444cc6eea0f801be7ebc6a7e4, stripped
```

Upon opening the binary with my favourite disassembler, some unusual things reveal themselves:

1. IDA is unable to find the main entrypoint (not that unusual, but more on that later)
2. Address calculations seemed to be done in some sort of relative manner. This might be standard practice on 32-bit PIE binaries, but I have never seen something like this and was thus confused in the beginning. (After the CTF I did indeed find out it was standard practice for 32-bit PIE binaries.)
3. `__libc_start_main` was called with non standard arguments.

```asm
lea     eax, (fini_func - 5657DFC8h)[ebx]
push    eax             ; fini
lea     eax, (init_func - 5657DFC8h)[ebx]
push    eax             ; init
push    ecx             ; ubp_av
push    esi             ; argc
push    ds:(actual_main_ptr - 5657DFC8h)[ebx] ; main
call    ___libc_start_main
```

*Note: All labels above (except `__libc_start_main`) were added by me much later, they all point to some location in the main binary.*

Normally, binaries call `__libc_start_main` with the binary's main function alongside `init` and `fini` from libc. This meant there was probably some shenanigans going on there.

Continuing on with more static analysis, we take a look at some of the other functions. One in particular caught my eye:

```c
int __cdecl do_arith_instr(int a1)
{
  unsigned int v1; // edi
  unsigned int v2; // eax
  int result; // eax

  v1 = (*(int (__cdecl **)(_DWORD, _DWORD))(**(_DWORD **)(a1 + 16) + 8))(**(_DWORD **)(a1 + 16), 0);
  v2 = (*(int (__cdecl **)(_DWORD, _DWORD))(*(_DWORD *)(*(_DWORD *)(a1 + 16) + 4) + 8))(
         *(_DWORD *)(*(_DWORD *)(a1 + 16) + 4),
         0);
  switch ( *(_DWORD *)a1 )
  {
    case 0:
      result = v1 == v2;
      break;
    case 1:
      result = v1 << v2;
      break;
    case 2:
      result = v1 >> v2;
      break;
    case 3:
      result = v1 ^ v2;
      break;
    case 4:
      result = v1 + v2;
      break;
    case 5:
      result = v1 - v2;
      break;
    case 6:
      result = v1 * v2;
      break;
    case 7:
      result = v1 != 0 && v2 != 0;
      break;
    case 8:
      result = v1 < v2;
      break;
    case 9:
      *(_DWORD *)v1 = v2;
      result = 0;
      break;
    default:
      exit(0);
      return result;
  }
  return result;
}
```

Aptly renamed, the function seems to implement a few arithmetic instruction and chooses which one to execute, based on it's input. This means we are dealing with some kind of VM and we probably had to reverse how it works and what it is executing.

Looking at the aforementioned custom `init` function, we see that it's just the normal libc `init` routine, calling first `__gmon_start__`, then going on to call all the initializers. Not sure why this was embedded into the binary here, maybe to make it more annyoing to reverse?

```c
int init_func() // called by __libc_start_main
{
  gmon_start();
  result = init_array;
  v4 = &init_array_end - init_array;
  if ( !v4 )
    return result;
  v5 = 0;
  do
    result = init_array[v5++]();
  while ( v4 != v5 );
  return result;
```

Nextup, we have the first function inside `init_array` not being a libc function. Trying to look at the decompiled version, gives us the following amusing IDA error message:

![too_big_function](https://i.imgur.com/Dq4vVYp.png)

Disgusted by the thought of having to look at more assembly, I decided it was time to switch over to dynamic analysis, after a quick pit stop at the final init function:

```c
_DWORD *maybe_main()
{
  _DWORD *result; // eax

  result = main_funcs;
  main_funcs[2] = &puts - 396320881;
  main_funcs[7] = 0;
  main_funcs[6] = 0;
  main_funcs[3] = 0;
  main_funcs[1] = (char *)&_isoc99_scanf - 1585299812;
  main_funcs[0] = &memset - 396098936;
  main_funcs[9] = "Ow!";
  main_funcs[5] = "%36s";
  main_funcs[8] = "Wow!";
  main_funcs[4] = "Ah?";
  return result;
}
```

This just initializes some global memory, for later.
Stepping into the main function, we are greeted with very little:

```c
int actual_main@()
{
  ((void (__cdecl *)(int *, _DWORD))*(&initial_node + 2))(&initial_node, 0);
  return 0;
}
```

Stepping further into the function residing at `initial_node + 2`, the name of the challenge starts to make sense:

```c
int __cdecl exec_arr_node_return_last2(int a1)
{
  unsigned int v1; // ebx
  int v2; // eax
  int result; // eax

  if ( !*(_DWORD *)(a1 + 12) )
    return -1;
  v1 = 0;
  do
  {
    v2 = *(_DWORD *)(*(_DWORD *)(a1 + 16) + 4 * v1++);
    result = (*(int (__cdecl **)(int, _DWORD))(v2 + 8))(v2, 0);
  }
  while ( *(_DWORD *)(a1 + 12) > v1 );
  return result;
}
```

The function references some array at an offset to the first argument and executes (at the same offset as before!) for every array element. By this point, I guessed based on the name of the challenge, that we are dealing with an execution tree, specifically the VM is executing the tree. Stepping further into the tree, I encountered some more functions (including the aforementioned arithmetic one) and was able to piece together how a node in the execution tree looks like:

```c
struct __attribute__((aligned(4))) node
{
  int field_0; // usually arg1
  int field_4; // usually arg2
  int (__cdecl *visit_func)(node *, _DWORD);
  int num_children;
  node **children;
};
```

Since I didn't want to have the debugger running constantly, I made a memory snapshot of the binary in IDA. Equipped with the struct and memory snapshot, I dug through part of the tree manually to find all visitor functions and how they are used. I also realized that the type of a node is entirely determined by it's visitor function, which made scripting a bit more annyoing later. I found the following types of nodes

#### Arithmetic
Executes some Arithmetic (or Logical) Instruction on its two children. Instruction is based on `field_0`.
<div style="overflow: hidden;">
<iframe src="http://galli.me/0ctf/#1448608896" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

#### MemOffset
Basically the `lea` instruction, calculates `base + scale * offset`, where `base` is result of its first child, `scale = field_4 == 1 ? 1 : 4` and offset is the result of its second child.

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448603176" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

#### Deref
This is a weird one. If `field_0` is 0, it does nothing and just passes the result through. If it is 1, it will try to dereference the result of its first child. If `field_4` is 1, it will treat it as a `char*`, otherwise as a `uint32_t*`.


<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448622876" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

#### Conditional
Executes either the second child (`true`) or the third child `false`, depending on the result of its first child.

*(No example, as the only conditional in the graph sits at the very root, check out the final graph below)*

#### Call
Calls the address supplied by its first child. The number of arguments is determined by the number of children and all children after the first one as treated as the arguments.

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448603256" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

#### Malloc
Calls malloc with `field_0` supplying the size. The resulting pointer is stored in `main_funcs`, whith the index supplied by `field_4`.

#### ExecSingle
This is actually two different ones, one of them returns the result of the first only child, while the other still executes it, but will always return 0.

*(These were removed in the visualization, since they are useless)*

#### Loop
Initially, the first child is executed, i.e. the loop initializer. Then, we loop until the third node returns false, i.e. the loop condition. After the loop condition is checked, we execute the loop body (child number four). Finally, we execute the loop increment, child number five.

*(Child number two is unused)*

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448604316" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

#### Sequential
Executes the child nodes in order and returns the result of the last child node.

#### Constant
Returns `field_0` and as such is akin to a constant.

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448617716" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

#### GetMain
Returns `main_funcs[field_0]`. This is used to access the functions stored there, as well as storing temporary stuff (like the flag).

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448613836" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

Having explored all the different node types, I wrote an IDAPython script to dump the whole tree in simple text form for more detailed analysis. One can immediately see, that the root of the tree is a sequential node, with 5 statements:

1. `flag_buffer = malloc(80)`
2. `memset(flag_buffer, 0, 80)`
3. `puts("Ah?")`
4. `scanf("%36s", flag_buffer)`
5. Conditional node with a lot more complicated subtree

So we truly are dealing with your standard flag checker ;). By looking at the conditional statement, we notice that it's first combining a bunch of other subtrees with an arithmetic node (operation 7, so both children need to return true). This makes sense and I assumed it was checking each part (however big that might be) of the flag individually.

By analyzing one such subtree, we can get a closer idea of whats going on. The tree starts again with an arithmetic node, but this time the operation is equal. Again, this seemed like your standard flag checker construct. However, both children of the equals node are very different. One child is just a long chain of arithmetic nodes and calculates the constant to compare the other child against. I wrote some additions to my script, that would run through nodes that were able to be immediately calculated (such as this "constant" sub tree) and got the constants I needed.

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448602036" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

Next I investigated the other child of the equals node. This was much simpler: A sequential node and a loop. The sequential node first initializes the loop index as well as a temporary buffer, both 4 bytes big (i.e. a `uint32_t`). Then it also loads 4 characters from the flag buffer into the temporary buffer (at an offset depending on which equals node you are looking at). Based on the fact that all other equals nodes looked very similar and even used the exact same loop node, I figured the program just goes through the flag and checks four bytes at a time. Finally we get to the important part, the loop responsible for calculating a value that is then compared against the constant.

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448623916" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

The loop is very simple, it iterates 100'000 times and it's body is basically the following:

```c
uint32_t temp = *(uint32_t*)temp_buffer;
temp = temp ^ (temp << 13);
temp = temp ^ (temp >> 17);
temp = temp ^ (temp << 5);
*(uint32_t*)temp_buffer = temp;
```

<div style="overflow: hidden;">
<iframe src="https://galli.me/0ctf/#1448604316" scrolling="no" width="100%" height="500px" frameBorder="0" ></iframe>
</div>

Simple enough right? Just fire up z3 and enter those constants along with the above loop and you get your flag? Unfortunately not, z3 is not happy at all with the loop and never finished when I tried. So I then wanted to figure out a way to simplify the loop. I defined an equivalent version in python and tried different things in `ipython`. Quickly, I found the following identity:

```python
def check(num):
    # loop mentioned above implemented with python

a, b = # any uint32 number
check(a ^ b) == check(a) ^ check(b)
```

This made it very easy to brute force, since I can just create a LUT per byte and then iterate over all 32-bit integers. With a LUT I got the flag in mere seconds: `flag{HEY!Lumpy!!W@tcH_0ut_My_TrEe!!}`.

You can check out a more interactive version of the full flag check [here](https://galli.me/0ctf/full.html).

For solver and more, see the GitHub repository [here](https://github.com/galli-leo/tctf2020/happy_tree).