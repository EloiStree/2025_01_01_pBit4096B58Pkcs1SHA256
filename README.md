
# 2025_01_01_pBit4096B58Pkcs1SHA256

The RSA format is used in my authentication with MetaMask Coaster because it runs on all platforms in Unity3D.  
(You should use ECC coaster in Rust and Python for many reasons.)

Unity doesn't have a crypto library and uses an older version of C#.  
So, if you want to use asymmetric keys, you're locked into the RSA pattern.

After trial and error, I learned that PKCS1 with SHA256 is commonly used.

Since 512 and 1024-bit keys are close to being a security problem, and I can't choose ECC in Unity, I didn't take the risk and directly used a 4096-bit key size.  
I'm only using it for the handshake.

As I need to pass the public key in the URL `?q=`, the XML file is parsed in a Base58 format.

It's not the best solution, I suppose, but until I find a way to make a signer compatible with MetaMask/Ethereum that runs on all platforms (99% sure), I am a bit stuck here.

You can find a sample using Python to understand what I means and how I am using it with MetaMask sign in.

Find the code for Unity3D in here, Mask Signer:  
[https://github.com/EloiStree/2025_01_01_ClipboardableAssymentricMetaCoasterUnity3D.git](https://github.com/EloiStree/2025_01_01_ClipboardableAssymentricMetaCoasterUnity3D.git)    
    
It is going to be used here, first:  
[https://github.com/EloiStree/2025_01_01_HelloMegaMaskPushToIID](https://github.com/EloiStree/2025_01_01_HelloMegaMaskPushToIID)  
