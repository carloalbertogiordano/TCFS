# TCFS - Transparent Cryptographic Filesystem
TCFS is a transparent cryptographic filesystem designed to secure files mounted on a 
Network File System (NFS) server. It is implemented as a FUSE (Filesystem in Userspace)
module along with a user-friendly helper program. TCFS ensures that files are encrypted 
and decrypted seamlessly without requiring user intervention, providing an additional 
layer of security for sensitive data.

## Disclamer

**Note:** This project is currently in an early development stage and should be considered
as an alpha version. This means there may be many missing features, unresolved bugs,
or unexpected behaviors. The project is made available in this phase for testing and
evaluation purposes and should not be used in production or for critical purposes.
It is not recommended to use this software in sensitive environments or to store
important data until a stable and complete version is reached. We appreciate any feedback,
bug reports, or contributions from the community that can help improve the project. 
If you decide to use this software, please **don't do it**.
Thank you for your interest and understanding as we work to improve the project and make 
it stable and complete.

## Features
- Transparent Encryption: TCFS operates silently in the background, encrypting and 
decrypting files on-the-fly as they are accessed or modified. Users don't need to worry
about managing encryption keys or performing manual cryptographic operations.
- FUSE Integration: TCFS leverages the FUSE framework to create a virtual filesystem that
integrates seamlessly with the existing file hierarchy. This allows users to interact 
with their files just like any other files on their system.
- Secure Data Storage: Files stored on an NFS server can be vulnerable during transit or
at rest. TCFS addresses these security concerns by ensuring data is encrypted before it leaves the client system, offering end-to-end encryption for your files.
- Transparency: No modifications to the NFS server are required.

## Getting Started
### Prerequisites
- FUSE: Ensure that FUSE and FUSE-dev are installed on your system. You can usually install it using
your system's package manager (e.g., apt, yum, dnf, ecc).
- OpenSSl: Install OpenSSL and its development package.
### Build
- Clone the TCFS repository to your local machine:
<pre>
<code>
git clone https://github.com/ada-fs/ptfs.git
</code>
</pre>
- Compile: Run the compilation script (Only the FUSE module is avilable at the moment, the whole project has not been implemented yet)
<pre>
<code>
chmod +x build-fs.sh; ./build-fs.sh;
</code>
</pre>

## Usage
### Mount an NFS share using TCFS:
First, mount the NFS share to a directroy, this directory will be called sourcedir.
This will be done by the helper program in a future release.
<pre>
<code>
    ./bin/tcfs /fullpath/sourcedir /fullpath/destdir
</code>
</pre>
Access and modify files in the mounted directory as you normally would. TCFS will handle 
encryption and decryption automatically.

### Unmount the NFS share when you're done:
<pre>
<code>
    fusermount -u /fullpath/destdir
</code>
</pre>
then unmount the NFS share.


## Contributing
Contributions to TCFS are welcome! If you find a bug or have an idea for an improvement,
please open an issue or submit a pull request on the TCFS GitHub repository.

## License
This project is licensed under the GPLv3 License - see the LICENSE file for details.

## Acknowledgments
TCFS is inspired by the need for secure data storage and transmission in NFS environments.
Thanks to the FUSE project for providing a user-friendly way to create custom filesystems.

**Inspiration from TCFS (2001):** This project draws substantial inspiration from an 
earlier project named "TCFS" that was developed around 2001. While the original source code
for TCFS has unfortunately been lost over time, we have retained valuable documentation 
and insights from that era. In the "TCFS-2001" folder, you can find historical 
documentation and design concepts related to the original TCFS project. Although we are 
unable to directly leverage the source code from the previous project, we have taken 
lessons learned from its design principles to inform the development of this current
TCFS implementation. We would like to express our gratitude to the creators and 
contributors of TCFS for their pioneering work, which has influenced and inspired our 
efforts to create a modern TCFS solution. Thank you for your interest in this project 
as we continue to build upon the foundations set by the original TCFS project.
