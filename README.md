# sphinX64
Simple linux x64 binary password "protector"

It uses infection method described in Silvio Cesare's article ["Unix ELF parasite and virus" ](<http://download.adamas.ai/dlbase/Stuff/VX%20Heavens%20Library/vsc01.html>) (from 1998 <sad_face.png>)

You can build it with `g++ -std=c++11 sphinx64.cpp -o sphinx64`  
stub.asm and it's arguments (via sprintf in sphinx64.cpp) are customizable

### Example usage:
> $ cp /bin/ls ls_test  
> $ ./sphinx64 ls_test sup3r_l0ng_p455w0rd_4lm0st_0ne_tim3_p4d  
> ... lots of debug info ...  
> $ ./ls_test -all  
> sphinx64  
> password:sup3r_l0ng_p455w0rd_4lm0st_0ne_tim3_p4d  
> total 224  
> drwxr-xr-x  3 root root   4096 Oct  2 14:16 .  
> drwxr-xr-x 11 root root   4096 Sep 22 16:59 ..  
> -rwxr-xr-x  1 root root 122376 Oct  2 14:16 ls_test  
> -rw-r--r--  1 root root   1056 Sep 24 15:51 simple_utils.h  
> -rwxr-xr-x  1 root root  15376 Oct  2 14:16 sphinx64  
> -rw-r--r--  1 root root   6751 Oct  2 12:46 sphinx64.cpp  
> -rw-r--r--  1 root root   1095 Oct  2 14:16 stub.asm  
> -rw-r--r--  1 root root    197 Oct  2 14:16 stub.o  
> test files ...

### WARNING!  
You should backup your elf_x64 before trying this there is no warranty it works as expected!