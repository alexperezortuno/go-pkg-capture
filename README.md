# go-pkg-capture

## Dependencies

Ubuntu:
```shell
sudo apt install libpcap-dev
```

## Build

```shell
go build
```

### Help

```shell
./go_capture -h
```

### Usage

Show list of available interfaces:

```shell
./go_capture -l
```

```shell
./go_capture -d <interface>
```

```shell
./go_capture -d <interface> -t <seconds>
```
```

```shell
./go_capture -d <interface> -t <seconds> -e <file-extension>
```
