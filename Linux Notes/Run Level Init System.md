**Run Level Init System**

What are init 0, init 1, init 2 ,init 3, init 4, init 5, init 6, init s, init S ?

init 0 : Shutdown (goes thru the /etc/rc0.d/* scripts then halts)

init 1 : Single user mode or emergency mode means no network no multitasking is present in this mode only root has access in this runlevel.

init 2 : No network but multitasking support is present .

init 3 : Network is present multitasking is present but with out GUI .

init 4 : It is similar to runlevel 3; It is reserved for other purposes in research.

init 5 : Network is present multitasking and GUI is present with sound etc.

init 6 : This runlevel is defined to system restart.

init s : Tells the init command to enter the maintenance mode. When the

system enters maintenance mode from another run level, only the system console is used as the terminal.

init S : Same as init s.

init m : Same as init s and init S.

init M : Same as init s or init S or init m.