# cryptogopher
Go library for accessing Cryptomator vaults (https://cryptomator.org)

## Usage
Open a vault at the specified location and with the specified passphrase.
```golang
vault, err := cryptogopher.Open(vaultLocation, passphrase)
```

Get the root directory from the vault and then output its contents
```golang
rootDir := vault.GetRootDirectory()
fmt.Println("--- Root Content ---")
rootDir.Print()
```

Get a sub directory from the vault at the path /test/inner and output its contents
```golang
fmt.Println("--- test/inner/ Content ---")
innerDir := rootDir.GetSubDirectory("test/inner")
innerDir.Print()
```

Create a new file in the root directory and write some text to it
```golang
newFile, err := rootDir.CreateFile("hello.txt")
newFile.WriteChunk([]byte("Hello from encrypted data!"), 0)
```

Read in the first chunk of the file (in this case the whole file) and print it to the command line
```golang
chunkData, err := newFile.ReadChunk(0)

fmt.Println(string(chunkData))
```
