Tool for opening Disk Cryptor (DiskCryptor) 1.1.846.118 partitions or disks in Linux. Only supports plain password approach.

NOTE: main.c is full AI slop. Other components may have been edited by AI. Mainly tested with encrypted partitions, not fully encrypted disks. Proceed with caution.

CERTIFIED: ⭐ Works on my machine :)

Requires dmsetup. Run `./build.sh` to build.

## Usage

```
dcrypt_tool open <device> <name> [--offset-sectors N] [-v]
dcrypt_tool close <name>
dcrypt_tool resize <device> <old-size-sectors> <new-size-sectors> [--offset-sectors N] [-v]
```

If you put your password into the `DC_PASSWORD` environment variable, you won't be prompted for it.

### open

```
dcrypt_tool open <device> <name> [--offset-sectors N] [-v]
```

Opens the disk/partition as `/dev/mapper/<name>`. You can now use the usual tools, like `mount` (for partitions) or `losetup` (for disks).

### close

```
dcrypt_tool close <name>
```

Closes the disk/partition at `/dev/mapper/<name>`. You may need to unmount or detach child devices beforehand.

### resize

```
dcrypt_tool resize <device> <old-size-sectors> <new-size-sectors> [--offset-sectors N] [-v]
```

**Growing:**

WARNING: This procedure seems to work (filesystem is mountable afterwards), but it seems to make the disk unbootable (NTLDR causes a triple fault). More research required.

```
DISK=/dev/sdX
PART=0
MNAME=dcrypt
OLDSIZE=$(blockdev --getsz ${DISK}${PART})
growpart $DISK $PART
NEWSIZE=$(blockdev --getsz ${DISK}${PART})
dcrypt_tool resize ${DISK}${PART} $OLDSIZE $NEWSIZE
dcrypt_tool open ${DISK}${PART} $MNAME
#ntfsfix /dev/mapper/$MNAME # optional??
ntfsresize --force --size $(blockdev --getsize64 /dev/mapper/$MNAME)
dcrypt_tool close $MNAME
```

**Shrinking:**

TODO
