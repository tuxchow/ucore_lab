#Lab1 Report

##练习1
---
1.操作系统镜像文件ucore.img是如何一步一步生成的？(需要比较详细地解释Makefile中每一条相关命令和命令参数的含义，以及说明命令导致的结果)

>	首先通过echo命令回显如下信息

	+ cc kern/init/init.c 
>	接下来通过gcc工具将init.c编译为init.o库文件，参数涵义为
-I 指定include目录 -fno-builtin 取消buitin优化 -Wall 生成所有警告信息 -ggdb 生成gdb的可以使用的调试信息 -m32 生成32位代码 -gstabs 以stabs格式声称调试信息 -nostdinc 不使用C标准库-fno-stack-protector 不使用栈溢出保护-c 将init.c编译成为init.o库文件-o 指定输出文件名
	
	gcc -Ikern/init/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/init/init.c -o obj/kern/init/init.o
	
>	然后同上方法编译了许多.o库文件，不再赘述

```
+ cc kern/libs/readline.c
gcc -Ikern/libs/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/libs/readline.c -o obj/kern/libs/readline.o
+ cc kern/libs/stdio.c
gcc -Ikern/libs/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/libs/stdio.c -o obj/kern/libs/stdio.o
+ cc kern/debug/kdebug.c
gcc -Ikern/debug/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/debug/kdebug.c -o obj/kern/debug/kdebug.o
+ cc kern/debug/kmonitor.c
gcc -Ikern/debug/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/debug/kmonitor.c -o obj/kern/debug/kmonitor.o
+ cc kern/debug/panic.c
gcc -Ikern/debug/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/debug/panic.c -o obj/kern/debug/panic.o
+ cc kern/driver/clock.c
gcc -Ikern/driver/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/clock.c -o obj/kern/driver/clock.o
+ cc kern/driver/console.c
gcc -Ikern/driver/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/console.c -o obj/kern/driver/console.o
+ cc kern/driver/intr.c
gcc -Ikern/driver/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/intr.c -o obj/kern/driver/intr.o
+ cc kern/driver/picirq.c
gcc -Ikern/driver/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/picirq.c -o obj/kern/driver/picirq.o
+ cc kern/trap/trap.c
gcc -Ikern/trap/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/trap/trap.c -o obj/kern/trap/trap.o
+ cc kern/trap/trapentry.S
gcc -Ikern/trap/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/trap/trapentry.S -o obj/kern/trap/trapentry.o
+ cc kern/trap/vectors.S
gcc -Ikern/trap/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/trap/vectors.S -o obj/kern/trap/vectors.o
+ cc kern/mm/pmm.c
gcc -Ikern/mm/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/mm/pmm.c -o obj/kern/mm/pmm.o
+ cc libs/printfmt.c
gcc -Ilibs/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/  -c libs/printfmt.c -o obj/libs/printfmt.o
+ cc libs/string.c
gcc -Ilibs/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/  -c libs/string.c -o obj/libs/string.o
```
>	之后使用ld工具将之前编译好的.o库文件链接成kernel文件，参数涵义为 -m elf_i386 生成elf_i386格式的文件 -T 指定链接脚本 -nostdinc 不使用C标准库 -o 指定输出文件名
	
	+ ld bin/kernel
	ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel  obj/kern/init/init.o obj/kern/libs/readline.o obj/kern/libs/stdio.o obj/kern/debug/kdebug.o obj/kern/debug/kmonitor.o obj/kern/debug/panic.o obj/kern/driver/clock.o obj/kern/driver/console.o obj/kern/driver/intr.o obj/kern/driver/picirq.o obj/kern/trap/trap.o obj/kern/trap/trapentry.o obj/kern/trap/vectors.o obj/kern/mm/pmm.o  obj/libs/printfmt.o obj/libs/string.o
>	接下来又编译了bootblock的.o库文件然后将之链接起来，不在赘述

```
+ cc boot/bootasm.S
gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o
+ cc boot/bootmain.c
gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
+ cc tools/sign.c
gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
+ ld bin/bootblock
ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
'obj/bootblock.out' size: 488 bytes
```
>	最后使用dd拷贝工具创建ucore.img磁盘镜像，参数涵义为 if=输入文件（/dev/zero文件代表一个永远输出0的设备文件，使用它作输入可以得到全为空的文件） of=输出文件 count=blocks 仅拷贝blocks个块（块大小缺省为512B） seek=blocks 从输出文件开头跳过blocks个块后再开始复制 conv=notrunc 不截短输出文件。

>	所以如下指令，第一行先建立一个5120000B的空镜像，第二行将bootblock拷贝到镜像的初始位置，第三行将kernel拷贝到镜像中偏移量为512B的位置，完成了ucore.img的生成。

```
dd if=/dev/zero of=bin/ucore.img count=10000
10000+0 records in
10000+0 records out
5120000 bytes (5.1 MB) copied, 0.186047 s, 27.5 MB/s
dd if=bin/bootblock of=bin/ucore.img conv=notrunc
1+0 records in
1+0 records out
512 bytes (512 B) copied, 0.000565191 s, 906 kB/s
dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
146+1 records in
146+1 records out
74923 bytes (75 kB) copied, 0.00244174 s, 30.7 MB/s
```

2.一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？

>	通过阅读sign.c文件可知，主引导扇区特征为大小=512Byte，且最后2个字节内容为0x55AA。

##练习2
---
1.从CPU加电后执行的第一条指令开始，单步跟踪BIOS的执行。

>	CPU加电后执行的第一条指令是载入BIOS的指令，可以通过将lab1init文件中的continue行删去，保存后在lab1目录执行

	make lab1-mon

>	使qemu进入到CPU刚加电的状态，之后在qemu终端和gdb终端执行

	x /10i $pc
	stepi
	
>	即可单步跟踪BIOS的执行，部分结果如下。

```
0xfffffff0:  ljmp   $0xf000,$0xe05b
0x000fe05b:  cmpl   $0x0,%cs:0x65a4
0x000fe062:  jne    0xfd2b9
0x000fe066:  xor    %ax,%ax
0x000fe068:  mov    %ax,%ss
0x000fe06a:  mov    $0x7000,%esp
0x000fe070:  mov    $0xf3c4f,%edx
0x000fe076:  jmp    0xfd12a
0x000fe079:  push   %ebp
0x000fe07b:  push   %edi
0x000fe07d:  push   %esi
```

2.在初始化位置0x7c00设置实地址断点,测试断点正常。

>	通过在lab1init文件中的以下两行即可完成端点设置
	
	b *0x7c00
	continue
	
>	测试断点正常结果如下

```
Breakpoint 1, 0x00007c00 in ?? ()
(gdb) x /10i $pc
=> 0x7c00:	cli    
   0x7c01:	cld    
   0x7c02:	xor    %ax,%ax
   0x7c04:	mov    %ax,%ds
   0x7c06:	mov    %ax,%es
   0x7c08:	mov    %ax,%ss
   0x7c0a:	in     $0x64,%al
   0x7c0c:	test   $0x2,%al
   0x7c0e:	jne    0x7c0a
   0x7c10:	mov    $0xd1,%al

```

3.从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与bootasm.S和 bootblock.asm进行比较。

>	bootasm.S的部分代码如下,与上题在0x7c00处反汇编的代码比较，发现其完全一致。

```
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
seta20.1:
    inb $0x64, %al
    testb $0x2, %al
    jnz seta20.1
    movb $0xd1, %al
```


4.自己找一个bootloader或内核中的代码位置，设置断点并进行测试。

>	测试结果如下

```
(gdb) b *0x7c10
Breakpoint 2 at 0x7c10
(gdb) continue
Continuing.

Breakpoint 2, 0x00007c10 in ?? ()
(gdb) x /10i $pc
=> 0x7c10:	mov    $0xd1,%al
   0x7c12:	out    %al,$0x64
   0x7c14:	in     $0x64,%al
   0x7c16:	test   $0x2,%al
   0x7c18:	jne    0x7c14
   0x7c1a:	mov    $0xdf,%al
   0x7c1c:	out    %al,$0x60
   0x7c1e:	lgdtw  0x7c6c
   0x7c23:	mov    %cr0,%eax
   0x7c26:	or     $0x1,%eax

```

##练习3
---
1.为何开启A20，以及如何开启A20

>	因为A20的存在是为了乡下兼容低版本cpu而实现的模拟内存回绕的开关，只有开启A20才能访问全部4G内存。
>	
>	开启A20的方式：首先检测8042键盘控制器是否空闲，将0x64端口的数据读入寄存器%al，检测bit1位是否为1，如为1则input buffer有数据，控制器繁忙，此时跳转到seta20.1起始处继续判断。如为0，则空闲，此时将0xd1写入0x64端口，表示要写Output Port。之后继续检测8042键盘控制器是否空闲，如空闲则向0x60端口写入0xdf（11011111），将A20 bit置1，完成开启A20，代码如下。

```
seta20.1:
    inb $0x64, %al 
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al
    outb %al, $0x64

seta20.2:
    inb $0x64, %al 
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al
    outb %al, $0x60
```

2.如何初始化GDT表

>	由于GDT表和描述符已经存在于引导区中，只需用如下指令将其载入即可。

	lgdt gdtdesc

3.如何使能和进入保护模式

>	首先将%cr0寄存器的最后一位置为1，表示进入保护模式。之后跳转到protcseg部分，将数据段选择子赋值给%ax，%ds，%es，%fs，%gs，%ss寄存器，然后将%ebp清零指向底层调用，将%esp指向0x7c00，最后完成调用bootmain函数。

```
    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0

    ljmp $PROT_MODE_CSEG, $protcseg

.code32
protcseg:
    movw $PROT_MODE_DSEG, %ax
    movw %ax, %ds            
    movw %ax, %es            
    movw %ax, %fs            
    movw %ax, %gs            
    movw %ax, %ss            

    movl $0x0, %ebp
    movl $start, %esp
    call bootmain
```

##练习4
---
1.bootloader如何读取硬盘扇区的？

>	首先通过waitdisk()函数等待硬盘空闲，然后向I/O端口写入要读取一个扇区，接着把读取地址分别用一个byte传给四个端口，值得注意的是在给0x1f6端口传数据时需要将第4位设置成0以表示读取主盘数据，，之后向0x1f7端口发送读取命令，等待硬盘空闲后，将0x1f0中的数据读入到dst中，代码如下。

```
static void
waitdisk(void) {
    while ((inb(0x1F7) & 0xC0) != 0x40)
        /* do nothing */;
}

/* readsect - read a single sector at @secno into @dst */
static void
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}
```

2.bootloader是如何加载ELF格式的OS？

>	首先读取一个扇区的elf数据到ELFHDR，然后检查ELF头部信息中的e_magic数据信息是否与ELF_MAGIC相等以判断ELF是否合法，之后找到程序头部，将程序一一读取进内存中，最后从ELF的程序入口开始执行。

```

/* bootmain - the entry of bootloader */
void
bootmain(void) {
    // read the 1st page off disk
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
...
```

##练习5
---
1.实现函数调用堆栈跟踪函数 

>	实现代码如下，首先调用函数获得当前ebp和eip，之后通过将ebp转为指针然后对起进行加减完成对栈中参数的访问，最后调用print_debuginfo函数输出调试信息。与答案的功能实现基本相同，语法上有差异。

```
	  uint32_t ebp = read_ebp(), eip = read_eip();
      int i;
      for(i = 0; i < STACKFRAME_DEPTH; i++){
        cprintf("ebp:0x%08x eip:0x%08x args:0x%08x 0x%08x 0x%08x 0x%08x\n", ebp, eip, *((uint32_t *)(ebp+8)), *((uint32_t *)(ebp+12)), *((uint32_t *)(ebp+16)), *((uint32_t *)(ebp+20)));
        print_debuginfo(eip-1);
        eip = *((uint32_t *)(ebp+4));
        ebp = *((uint32_t *)ebp);
        if(ebp == 0)
            break;

      }
```

>	最后一行的含义为，ebp为0，表示到达栈底调用，此时eip为0x7d72，表示kern_init函数的返回地址
	
	\<unknow>: -- 0x00007d72 –



##练习6
----
1.中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

>	一个表项占8个字节，gd_ss表示中断处理代码的段选择子，gd_off_15_0和 gd_off_31_16分别表示段内偏移量的低16位和高16位。


2.请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。在idt_init函数中，依次对所有中断入口进行初始化。使用mmu.h中的SETGATE宏，填充idt数组内容。每个中断的入口由tools/vectors.c生成，使用trap.c中声明的vectors数组即可。

> 先定义外部变量__vectors，然后根据不同中断对应不同的权限进行初始化，最后使用lidt()函数将idt表进行载入，代码如下。与答案不同的是对于T_SYSCALL的权限，我赋值为用户态而答案则是内核态。

```
	extern uintptr_t __vectors[];
    int i;
    for(i = 0; i < 256; i++){
        if(i == T_SWITCH_TOK){
            SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_USER);
        } else if(i == T_SYSCALL){
            SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_USER);
        } else {
            SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
        }
    }
    lidt(&idt_pd);
```

3.请编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数中处理时钟中断的部分，使操作系统每遇到100次时钟中断后，调用print_ticks子程序，向屏幕上打印一行文字”100 ticks”。

>	对kern/driver/clock.c中的ticks进行累加，每加TICK_NUM次，进行输出，代码如下。

```
	ticks++;
	if(ticks % TICK_NUM == 0)
    	print_ticks();
	break;
```