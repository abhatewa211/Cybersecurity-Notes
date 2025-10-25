**Essential Linux Command 3**

13/39

Essential Linux Commands 3

I. **ln**- used to create a hard link or a symbolic link (symlink) to an existing file or directory. The use of a hard link allows multiple filenames to be associated with the same file since a hard link points to the inode of a given file, the data of which is stored on disk.

Syntax:

ln [OPTION]... [-T] TARGET LINK_NAME (1st form)

ln [OPTION]... TARGET... DIRECTORY (2nd form)

ln [OPTION]... -t DIRECTORY TARGET... (3rd form)

Switches SS

14/39

![[image11.png]]

II. **Less**- a terminal pager program used to view the contents of a text file one screen at a time. Unlike the more command, less allows backward navigation in the file and forward navigation.

Switches SS

15/39

![[image12.png]]

Syntax of `less` command in Linux

The basic syntax of the less command is as follows:

= less [options] filename

III. **id**- used to find out user and group names and numeric ID's (UID or group ID) of the current user or any other user in the server. This command is useful to find out the following information as listed below: User name and real user id. Find out the specific Users UID.

Synopsis:

16/39

id [OPTION]… [USER]

Options:

- -g : Print only the effective group id.
- -G : Print all Group ID’s.
- -n : Prints name instead of number.
- -r : Prints real ID instead of numbers.
- -u : Prints only the effective user ID.
- –help : Display help messages and exit.
- –version : Display the version information and exit.

IV. **TTY** - The tty command of the terminal basically prints the file name of the terminal connected to standard input. tty is short for teletype, but popularly known as a terminal it allows you to interact with the system by passing on the data (your input) to the system and displaying the output produced by the system.

**Options:**

- **s, --silent, --quiet:** Prints nothing, only returns an exit status.

V. **whoami**- used to display the username of the current user.

VI. **who**- a tool print information about users who are currently logged in. who command only see a real user who logged in.

Switches SS

17/39

![[image13.png]]

VII. **uname**- The term “uname” stands for “Unix Name,” and the command itself is designed to provide you with key

details about your.

Switches

18/39

![[image14.png]]

VIII. **lscpu**- provides details about various CPU-related components. To find specific information, such as the CPUs or sockets number, utilize grep to filter and extract the information from the output.

Switches

19/39

![[image15.png]]

IX. **lsusb**- used to display the information about USB buses and the devices connected to them.

Options

Some common options used with the lsusb command are:

20/39

- -v: Display detailed information about the USB devices.
- -t: Display a tree-like view of the USB devices.
- -s: Display information about a specific USB device, specified by its bus and device number. • -d: Display information about a specific USB device, specified by its vendor and product ID. • -D: Selects which device will be examined.

X. **lspci**- that prints ("lists") detailed information about all PCI buses and devices in the system.

Switches

![[image16.png]]

21/39

![[image17.png]]

![[image18.png]]

XI. **lsblk**- stands for 'list block devices', and as the name suggests, it is used to list out all block devices in a tree-like format. This powerful command can help you gather comprehensive information about each block device connected to your Linux system, including the disk partitions and their respective sizes.

22/39

Switches

![[image19.png]]

XII. **free**- allows you to check for memory RAM on your system or to check the memory statics of the Linux operating system.

Switches

23/39

![[image20.png]]

XIII. **date**- The "**date**" command in Linux is a simple but powerful tool used to display the current date and time, as well as set the system date and time.

Switches

24/39

![[image21.png]]

**Options**

The following are some useful command line options of the date command:

- **d, --date=STRING:** It is used to display time described by STRING.
- **-debug:** It is used to annotate the parsed date, and provide a warning about controversial usage to the stderr.• **f, --file=DATEFILE:** It is similar to the '--date' option.
- **I[FMT], --iso-8601[=FMT]:** It is used to display the date/time in ISO 8601 format.
- **R, --rfc-email:** It is used to display the date and time in RFC 5322 format. For example, Mon, 14 Aug 2006 02:34:56
- 0600.
- **-rfc-3339=FMT:** It is used to display date/time in RFC 3339 format.
- **r, --reference=FILE:** It is used to display the previous modification time of the FILE.• **s, --set=STRING:** It is used to set time described by STRING.
- **u, --utc, --universal:** It is used to display or set the UTC.
- **-help:** It is used to display the help manual.
- **-version:** It displays the version information.

XIV. **cal**- If a user wants a quick view of the calendar in the Linux terminal, cal is the command for you.

Options

- **cal -y** : Shows the calendar of the complete current year with the current date highlighted.• **cal [ [ month ] year]**Shows month calendar on the terminal with the current date highlighted.

25/39

- **cal (year)**Shows the whole calendar of the year.
- **cal -3** : Shows calendar of previous, current and next month

• **cal -j** : Shows the calendar of the current month in the Julian calendar format not in the default Gregorian calendar format. In Julian calendar format, the date does not reset to 1 after every month’s end i.e. after 31st Jan, Feb will start as 32nd Feb, not as 1st Feb. But in the Gregorian calendar format, the date is reset to 1 after every month’s end i.e after 31st Jan, Feb will start as of 1st Feb.

XV. **ifconfig**- stands for **interface configurator**. This command enables us to initialize an interface, assign IP address, enable or disable an interface. It display route and network interface. You can view IP address, MAC address and MTU (Maximum Transmission Unit) with ifconfig command.

26/39

![[image22.png]]

27/39

![[image23.png]]

XVI. **route**- By utilizing the route command, Linux administrators and users can establish static routes, enabling precise control over network connectivity and optimizing data transmission.

Switches

28/39

![[image24.png]]

29/39

![[image25.png]]

30/39

![[image26.png]]

31/39

![[image27.png]]

32/39

![[image28.png]]

![[image29.png]]

XVII. **History**- Linux history command is used to display the history of the commands executed by the user. It is a handy tool for auditing the executed commands along with their date and time.

Switches.

Options:

33/39

The following are some command-line options that are supported by the history command:

- **c**: It is used to clear the complete history list.
- **d** offset: It is used to delete the history entry at the position OFFSET.• **a**: It is used to append history lines.
- **n**: It is used to read all history lines.
- **r**: It is used to read the history file.
- **w**: It is used to write the current history to the history library.
- **p**: It is used to perform history expansion.
- **s**: It is used to append the ARGs to the history list as a single entry.

XVIII. **uptime**- It is used to find out how long the system is active (running). This command returns set of values that involve, the current time, and the amount of time system is in running state, number of users currently logged into, and the load time for the past 1, 5 and 15 minutes respectively.

Usage:

uptime [options]

Options:

-p, --pretty show uptime in pretty format

-s, --since system up since

XIX. **Shutdown**- The shutdown command in Linux is used to shutdown the system in a safe way. You can shutdown the machine immediately, or schedule a shutdown using 24 hour format.It brings the system down in a secure way. When the shutdown is initiated, all logged-in users and processes are notified that the system is going down, and no further logins are allowed.

Only root user can execute shutdown command.

**Options**

- r : Requests that the system be rebooted after it has been brought down.
- h : Requests that the system be either halted or powered off after it has been brought down, with the choice as to which left up to the system.
- H : Requests that the system be halted after it has been brought down.
- P : Requests that the system be powered off after it has been brought down.
- c : Cancels a running shutdown. TIME is not specified with this option, the first argument is MESSAGE.
- k : Only send out the warning messages and disable logins, do not actually bring the system down.