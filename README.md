# cfgdump
Windbg extension that allows you analyze Control Flow Guard map

# Supported commands:

!cfgcover - prints memory map that is covered by CFG map and shows which region are protected by CFG bits

!cfgrange \<address\> \<size\> - prints CFG bits for specified address range

!cfgdump - prints all CFG bits for whole address space
