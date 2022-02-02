# ExamPaperNDSS2022_RE_Tool

Reverse engineering package designed for analysing exam proctoring suites.

# Arguments and Usage
## Usage
```
usage: argdown [-h] [--cfg] [--pdd] [--segments] [--vm] [--webcam] [--microphone] [--insecureHttp] [--encryption] [--liveMemory] binary [binary ...]
```
## Arguments
### Quick reference table
|Short|Long            |Default|Description                                                                                  |
|-----|----------------|-------|---------------------------------------------------------------------------------------------|
|`-h` |`--help`        |       |show this help message and exit                                                              |
|     |`--cfg`         |       |print CFG of found functions (default: false)                                                |
|     |`--pdd`         |       |attempt to decompile found functions using Ghirda (default: false require)                   |
|     |`--segments`    |       |print the different code segment boundaries (default: false)                                 |
|     |`--vm`          |       |highlight virtual machine detection code segments (default: false)                           |
|     |`--webcam`      |       |highlight webcam related code segments (default: false)                                      |
|     |`--microphone`  |       |highlight microphone related code segments (default: false)                                  |
|     |`--insecureHttp`|       |highlight insecure http URLs being used in the binary (default: false)                       |
|     |`--encryption`  |       |highlight encryption related code segments and attempt to extract their keys (default: false)|
|     |`--liveMemory`  |       |execute the binary with a gdb hook for a more comprehensive analysis (default: false)        |

### `-h`, `--help`
show this help message and exit

### `--cfg`
print CFG of found functions (default: false)

### `--pdd`
attempt to decompile found functions using Ghirda (default: false require)

### `--segments`
print the different code segment boundaries (default: false)

### `--vm`
highlight virtual machine detection code segments (default: false)

### `--webcam`
highlight webcam related code segments (default: false)

### `--microphone`
highlight microphone related code segments (default: false)

### `--insecureHttp`
highlight insecure http URLs being used in the binary (default: false)

### `--encryption`
highlight encryption related code segments and attempt to extract their keys
(default: false)

### `--liveMemory`
execute the binary with a gdb hook for a more comprehensive analysis (default:
false)
