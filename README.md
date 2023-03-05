# Arcadyan WE420223-99 image sign tool

This tool helps you converting an OpenWRT image to something that can be
uploaded in the Arcadyan WE420223-99 web interface. We need to change things in
the TRX header so that the `arc_uploadhelper` tool on the device accepts the
uploaded firmware. This was tested on the KPN Experia WiFi 1.00.15 firmware
release. 

## Steps
1. The `arcadyan/dat.h` should contain the private keys for signing. They are
   not included in this repository. You need to create that file and fill
   variables like `const char DAT_0041d784[0x2c2]` with the key material.
2. Obtain an OpenWRT initramfs image. We need initramfs because the original
   firmware splits up the flash in A/B, OpenWRT uses a single partition. An
   initramfs image will still fit the A/B splitted partitioning scheme.
3. Convert the initramfs to a `.trx` file. The following script was extracted from the OpenWRT source code:

         #!/bin/bash
         echo -ne "hsqs" > $1.hsqs
         trx_magic=0x746f435d
         ./otrx create $1.trx -M ${trx_magic} -f $1 \
           -a 0x20000 -b 0x420000 -f $1.hsqs -a 1000
         dd if=/dev/zero bs=1024 count=1 >> $1.trx.tail
         echo -ne "HDR0" | dd of=$1.trx.tail bs=1 seek=$((0x10c)) count=4 \
           conv=notrunc 2>/dev/null
         dd if=$1.trx.tail >> $1.trx 2>/dev/null
         rm $1.hsqs $1.trx.tail

   The `otrx` tool is built when building the OpenWRT image.
4. After creating the TRX, compile this repository. Go to the `install`
   directory and run: `make -f unix/makefile CPUT= ANSISTD=1 arcadyan`
5. Sign the `.trx` file with `./arcadyan s initramfs-kernel.bin.trx
   initramfs-kernel_sign.trx`

