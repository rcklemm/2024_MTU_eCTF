# Michigan Technological University 2024 eCTF
This repository holds the implementation for MTU's secure MISC
design, as described by the `mtu_design_doc.pdf` specification.


## Layout
- `application_processor` - Code for the application processor
    - `project.mk` - Unchanged from reference design
    - `Makefile` - Some extra flags added for WolfSSL compilation, mostly unchanged from reference design
    - `inc` - Directory with c header files
      - `ap_messaging.h` - Defines our messaging struct and the routines for sending and receiving it over I2C
      - `crypto_util.h` - Defines our encryption, decryption, and hashing routines
      - `general_util.h` - Defines routines for TRNG and timing-resistant `memcmp`
    - `src` - Directory with c source files
      - `ap_messaging.c` - Implementation for `ap_messaging.h`
      - `crypto_util.c` - Implementation for `crypto_util.h`
      - `general_util.c` - Implementation for `general_util.h`
    - `wolfssl` - Contains wolfssl library source code for our crypto utilities
- `component` - Code for the components
    - `project.mk` - Unchanged from reference design
    - `Makefile` - Some extra flags added for WolfSSL compilation, mostly unchanged from reference design
    - `inc` - Directory with c header files
      - `comp_messaging.h` - Defines our messaging struct and the routines for sending and receiving it over I2C
      - `crypto_util.h` - Defines our encryption, decryption, and hashing routines. AP and Component copies are the same
      - `general_util.h` - Defines routines for TRNG and timing-resistant `memcmp`. AP and Component copies are the same
    - `src` - Directory with c source files
      - `ap_messaging.c` - Implementation for `ap_messaging.h`
      - `crypto_util.c` - Implementation for `crypto_util.h`. AP and Component copies are the same
      - `general_util.c` - Implementation for `general_util.h`. AP and Component copies are the same
    - `wolfssl` - Contains wolfssl library source code for our crypto utilities
- `deployment` - Code for deployment secret generation
    - `Makefile` - Securely generate a random AES encryption key and flash magic value for use between AP and Component in global_secrets.h
- `ectf_tools` - Unchanged from reference design
- `shell.nix` - Unchanged from reference design
- `custom_nix_pkgs` - Unchanged from reference design
- `mtu_design_doc.pdf` - Our final design document PDF

## Usage and Requirements

The Nix environment, Poetry environment, and build process should all work exactly as they do in the reference design. No additional setup is required, so refer to the reference design documentation for usage.