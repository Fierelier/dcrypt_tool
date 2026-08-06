Tool for opening Disk Cryptor (DiskCryptor) 1.1.846.118 partitions or
disks in Linux. Only supports plain password approach.

NOTE: This is full AI slop. Mainly tested with encrypted partitions, not
fully encrypted disks. Proceed with caution.

CERTIFIED: ⭐ Works on my machine :)

Requires dmsetup. Run ./build.sh to build.

* Usage:

dcrypt_tool <device> <name> [--offset-sectors N] [-v]

This opens the disk/partition as /dev/mapper/<name>. You can now use the
usual tools, like mount (for partitions) or losetup (for disks).

If you put your password into the DC_PASSWORD environment variable, the
device will be mounted without prompting you.


dcrypt_tool --close <name>

Closes the disk/partition at /dev/mapper/<name>. You may need to unmount
or detach your child device beforehand.
