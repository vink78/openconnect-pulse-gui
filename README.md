# openconnect-pulse-gui

This script provides a wrapper around [OpenConnect](https://www.infradead.org/openconnect/) which allows a user to log in through a WebKitGTK2 window.  This allows OpenConnect to be compatible with web-based authentication mechanisms, such as SAML.

## Requirements

The script requires python3.  The following packages are also required:

 - python-gi or python-gobject
 - webkit2gtk
 - openconnect

Instruction for specific distros can be found below.

### Debian/Ubuntu

    sudo apt install python3-gi gir1.2-webkit2-4.1 openconnect

### Fedora

    sudo yum install python-gi webkit2gtk3 openconnect

### Arch

    sudo pacman -S python-gobject webkit2gtk openconnect

## Installation

This repo can be downloaded with `git clone https://github.com/markus-meier74/openconnect-pulse-gui.git` or via the GitHub webpage.

Installation is easiest by creating a virtual python environment with venv.
The following instructions assume that the git repo was cloned to `${HOME}/scripts/vpn/openconnect-pulse-gui`.

    mkdir -p ${HOME}/scripts/vpn/venv
    python -m venv --system-site-packages ${HOME}/scripts/vpn/venv
    source ${HOME}/scripts/vpn/venv/bin/activate
    cd ${HOME}/scripts/vpn/openconnect-pulse-gui
    pip install .
    deactivate

# Configuring sudo
openconnect requires root privileges to configure the network interfaces for VPN. The `openconnect-pulse-gui` script embeds a web browser and should definitely not be run as root. The script will try to execute openconnect with sudo. The user requires access to the openconnect command via sudo which can be configured by creating a plain text file /etc/sudoers.d/openconnect with a content like this:

    # Allow all users that are in the "users" group to run /usr/bin/openconnect as root without asking for a password
    %users ALL=(root:root) NOEXEC, NOPASSWD: /usr/bin/openconnect

This file should be owned by root:root and have permissions 440.
    chown root:root /etc/sudoers.d/openconnect
    chmod 440 /etc/sudoers.d/openconnect

The privileges can be tailored to your needs as described in the sudo manual.

## Usage

Activate the virtual environment that has `openconnect-pulse-gui` installed. The `openconnect-pulse-gui` script should now be in your $PATH.

The only required required argument is the sign-in link / server URL.  Other arguments can be found by using `python openconnect-pulse-gui.py -h`.

If WebKit2 throws errors such as `KMS: DRM_IOCTL_MODE_CREATE_DUMB failed: Permission denied`,
disable Shared DMA buffer rendering by setting the environmental variable WEBKIT_DISABLE_DMABUF_RENDERER=1.

Here is an example bash script:

    #!/bin/bash
    . "${HOME}/scripts/vpn/venv/bin/activate"
    WEBKIT_DISABLE_DMABUF_RENDERER=1 openconnect-pulse-gui "vpn.cc.umanitoba.ca/staff"
    deactivate

## Login process

Anybody wishing to recreate this functionality either manually or using another library can with the following steps:

1. Send the user to the sign-in URL.  This will either give them the ability to log in directly or redirect them to an external authentication server.
2. Wait for a `Set-Cookie` header that contains the `DSID` cookie.  This is the authentication cookie used by Pulse Secure.
3. Pass the cookie to `openconnect` using `--protocol nc` and `-C 'DSID=<cookie-value>'`.  Note that some workflows may work with `--protocol pulse`, but at this time SAML-based logins do not.

This script was tested and works with Ivanti Secure with Microsoft Entra multi-factor authentication at the University of Manitoba.


