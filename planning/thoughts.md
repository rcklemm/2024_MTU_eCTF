The main thing we need to implement is our cryptographic handshake

```
A                                                      B
|-----enc(rng1, msg1)||hash(rng1, msg1)----------------|
|                                                      |
|-----enc(rng1+1,rng2,msg2)||hash(rng1+1,rng2,msg2)----|
|                                                      |
|-----enc(rng2+1,msg3)||hash(rng2+1,msg3)--------------|
|                                                      |
```

To do this, we probably want to define some sort of message struct:

```C
struct msg_t {
  uint64_t rng_challenge;
  uint64_t rng_response;
  
  enum msgtype_t type;
  
  // I think this max length is something we know. So this is probably the safest way to do it
  uint8_t data[MAX_I2C_LEN];

  uint8_t hash[HASH_LEN];
}
```


