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
it stable and complete :-).

## Technologies used
To achieve our goal many different auxiliary programs and tech has found its way in TCFS
- Securing the encryption Key
  - Keyutils
- Database management
  - MariaDB
- Documentation
  - Generated using Doxygen
  - Some documentation is currently missing
- Versioning
  - GitHub
- Code analysis
  - See the GitHub actions
- Code formatting
  - clang-format for C/C++ files

## Features
- Transparent Encryption: TCFS operates silently in the background, encrypting and 
decrypting files on-the-fly as they are accessed or modified. Users don't need to worry
about managing encryption keys or performing manual cryptographic operations. Now, the
encryption keys are managed by a REST server that integrates with the database and publishes the public keys of the users.
- FUSE Integration: TCFS leverages the FUSE framework to create a virtual filesystem that
integrates seamlessly with the existing file hierarchy. This allows users to interact 
with their files just like any other files on their system.
- Secure Data Storage: Files stored on an NFS server can be vulnerable during transit or
at rest. TCFS addresses these security concerns by ensuring data is encrypted before it leaves the client system, offering end-to-end encryption for your files.
- Transparency: No modification to the remote server is required.

## Getting Started
### Documentation
Documentation is lacking but it can be found [here](https://carloalbertogiordano.github.io/TCFS/)
### Prerequisites
- For the fuse module:
  - FUSE: Ensure that FUSE and FUSE-dev are installed on your system. You can usually install it using
  your system's package manager (e.g., apt, yum, dnf, ecc).
  - OpenSSl: Install OpenSSL and its development package.
- For the remote server (Unused for now) 
  - MariaDB: Install and start MariaDB
  - Go: Install a compiler for go
### Build
- Clone the TCFS repository to your local machine:
<pre>
<code>
git clone https://github.com/carloalbertogiordano/TCFS
</code>
</pre>
#### Build and run the userpace module
- Compile: Run the Makefile in the userspace-module directory
<pre>
<code>
make all
</code>
</pre>
- Create a configuration file
<pre>
<code>
mkdir ~/.tcfs
nano tcfs-config.yaml
</code>
</pre>
Write this in the config file
<pre>
<code>
source: "source directory"
destination: "destination directory"
key_id: "the id obtained by keyutils"
params: "-f" (keep this if you want fuse to not detach from terminal)
debug: DEBUG_ALL (you can chose between: DEBUG_NONE DEBUG_ERRORS, DEBUG_CALLS, DEBUG_ALL )
log_to_console: true or false

</code>
</pre>
- Run: Run the compiled file. 
<pre>
<code>
build/fuse-module/tcfs
</code>
</pre>

#### Build and run the REST server (Unused)
- Build and install: To install the daemon run this commands in the DaemonREST directory
<pre>
<code>
go build server
</code>
</pre>

#### Build and run the helper program (Unimplemented)
- Compile: Run the Makefile in the user directory
<pre>
<code>
make
</code>
</pre>
- Run: Run the compiled file
<pre>
<code>
build/tcfs_helper/tcfs_helper
</code>
</pre>

#### Kernel module
- This part of the project will not be developed in contrast to the original version of the TCFS filesystem

## Usage of the fuse module
### This module is currently not in development


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

## Roadmap
- Key management:
  - ~~Store a per-file key in the extended attributes and use the user key to decipher it.~~
  - ~~Implement a kernel module to rebuild the private key to decipher the files. This module will use a certificate and your key to rebuild the private key~~
  - Implement key recovery.
- Implement threshold sharing files (done in the server, fuse module is missing this feature at the moment).
- Server:
  - ~~Implement user registration and deregistration~~
  - ~~Implement accessing and creation of shared files~~
  - Update the userspace module to handle the features that the daemon provides 
