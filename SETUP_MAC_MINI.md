# Setting Up the 2018 Mac Mini as a Test Machine

## Hardware: 2018 Mac Mini (Intel, DDR4 — not DDR3*)
*Note: 2018 Mac Mini actually uses DDR4 SO-DIMMs, not DDR3.
The Intel i3/i5/i7 models all have great Linux support.

## Step 1: Create Arch Linux USB Installer

On your main Mac, download and flash:
```bash
# Download latest Arch ISO
curl -O https://geo.mirror.pkgbuild.com/iso/latest/archlinux-x86_64.iso

# Find your USB drive
diskutil list

# Flash it (replace diskN with your USB)
sudo dd if=archlinux-x86_64.iso of=/dev/rdiskN bs=4m status=progress
```

## Step 2: Boot Mac Mini from USB
1. Plug USB into Mac Mini
2. Hold Option (⌥) key while powering on
3. Select "EFI Boot" (the USB drive)

## Step 3: Install Arch Linux

```bash
# Connect to WiFi
iwctl
station wlan0 connect YOUR_WIFI_NAME

# Partition the disk
fdisk /dev/sda
# Create: 512MB EFI partition (type EFI), rest as Linux filesystem

# Format
mkfs.fat -F32 /dev/sda1
mkfs.ext4 /dev/sda2

# Mount
mount /dev/sda2 /mnt
mount --mkdir /dev/sda1 /mnt/boot

# Install base system + kernel + dev tools
pacstrap /mnt base linux linux-headers linux-firmware \
    base-devel git vim networkmanager \
    intel-ucode grub efibootmgr

# Generate fstab
genfstab -U /mnt >> /mnt/etc/fstab

# Chroot in
arch-chroot /mnt

# Set timezone, locale, hostname
ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime
echo "nexus-dev" > /etc/hostname
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen

# Set root password
passwd

# Install bootloader
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
grub-mkconfig -o /boot/grub/grub.cfg

# Enable networking
systemctl enable NetworkManager

# Create your user
useradd -m -G wheel nexus
passwd nexus
echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers

# Exit and reboot
exit
umount -R /mnt
reboot
```

## Step 4: Post-Install Setup

```bash
# Login as nexus user, connect WiFi
nmcli device wifi connect YOUR_WIFI_NAME password YOUR_PASSWORD

# Install kernel headers (needed to compile our module)
sudo pacman -S linux-headers dkms

# Install dev tools
sudo pacman -S gcc make pkg-config

# Clone our project
git clone YOUR_REPO_URL nexus-nt
cd nexus-nt/module

# Build the kernel module
make

# Load it!
make load

# Check it worked
dmesg | tail -20
cat /proc/nexus_nt
```

## Step 5: Test Cycle
```bash
# Edit code on Mac → push to git → pull on Mac Mini → rebuild

# Or SSH into the Mac Mini from your main Mac:
ssh nexus@MAC_MINI_IP

# Then edit locally, scp to Mac Mini:
scp -r module/ nexus@MAC_MINI_IP:~/nexus-nt/module/
ssh nexus@MAC_MINI_IP "cd ~/nexus-nt/module && make clean && make && make load"
```

## What We Test First
1. `make` compiles without errors
2. `insmod nexus_nt.ko` loads without kernel panic
3. `cat /proc/nexus_nt` shows fake EPROCESS list matching `ps aux`
4. `cat /proc/nexus_nt` shows fake module list (ntoskrnl, hal, CI, etc.)
5. SSDT is built with 462 entries
6. Object directory has \Device, \Driver, \ObjectTypes
