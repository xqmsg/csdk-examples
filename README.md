# XQ C SDK Examples

This project contains sample projects that demonstrate how to use the [XQ C Library](https://github.com/xqmsg/csdk-core):

* **Starter Tutorial:** Demonstrates basic usage of the XQ library.
* **Video Proxy Demo:** A sample project demonstrating encrypted data proxy, suitable for media streaming.

## Installation

Both projects require the [XQ C Library](https://github.com/xqmsg/csdk-core) to be available on the target system. 

Once this is done, build the sample projects.The path to the XQ C build folder and headers will be necessary in this step:

```shell
mkdir build && cd build
cmake -Dsdk=/path/to/xqc/build -Dheaders=/path/to/xqc/headers .. 
make
```

To build an Xcode project, add the `-G Xcode` flag to the `cmake` command above:
```shell
mkdir xcode && cd xcode
cmake -G Xcode -Dsdk=/path/to/xqc/build -Dheaders=/path/to/xqc/headers .. 
```


## 1. Starter Tutorial
No additional configuration is required. Navigate to the `bin` folder and run the application, providing the path to a valid `xq.ini` configuration file, as well as a valid email address:

```shell
cd bin
./starter /path/to/xq.ini email@domain.com
```

The tutorial performs all the following steps.
* SDK initialization
* User access request
* PIN validation
* User information retrieval
* Message encryption
* Message decryption
* Message revocation


## 2. Video Proxy Demo

To use the proxy, you will need to have ffmpeg installed. 

**Linux:**

```shell
sudo apt install ffmpeg
```
**MacOS ( with Homebrew):**

```shell
brew install ffmpeg
```
A startup helper script may also be copied from the `extras` folder to `build/bin`:

```shell
cp ../extra/start-proxy bin
 chmod +x bin/start-proxy
```

 **Note:** If the`start-proxy` file was copied, its parameters may need to be updated as desired. A description of all parameters are shown at the end of this doc. The `xq.ini` configuration file should also be updated with valid API keys if necessary.

Once all values are up to date, the proxy can be started with the `start-proxy` script:

```shell
cd bin
./start-proxy
```

**Start streaming data from a camera to the video proxy**
Note that another console window will need to be opened, or the previous command moved to background.

**Linux:**

```shell
ffmpeg -f v4l2 -i /dev/video0 -profile:v high -pix_fmt yuv420p -level:v 4.1 -preset ultrafast -tune zerolatency -vcodec libx264 -r 60 -b:v 256k -s 640x360 -f mpegts -flush_packets 0 udp://0.0.0.0:3081
```

**MacOS:**

```shell
ffmpeg -f avfoundation -framerate 30 -i default -preset fast  -s 640x360 -tune zerolatency  -framerate 60 -f mpegts udp://0.0.0.0:3081
```


The final argument above is the host and port where packets are sent to. This  should correspond with the `host` and `enc_port` parameters set in start-proxy. The parameter `/dev/video0` refers to the camera on the local device.

Encrypted video packets should now be getting streamed to the `enc_out_host` on `enc_out_port` (pointing to the 2nd device which will receive the signal). The above ffmpeg settings only do video. This can be configured for audio as well (provided there is a microphone available).

Repeat the above steps on a 2nd machine (again, making sure to configure the settings correctly).

Finally, start up a media player (e.g. VLC) on each of the devices, and begin playback of the network stream on port 5000 or whatever port is set as `dec_out_port` on the local proxy.

**Start-Proxy Arguments**

| Parameter Name   | Description                                                  | Default  |
| ------------- | ------------------------------------------------- | ---------------- |
| **host**         | The host IP address that this application will be bound to. | 0.0.0.0  |
| **enc_port**     | The host port for incoming packets that need to be encrypted. After encryption, UDP packets will be sent to `enc_out_host` on port `enc_out_port`. | 3081     |
| **dec_port**     | The port on the host for incoming packets that need to be decrypted. After decryption, UDP packets will be sent to `dec_out_host` on port `dec_out_port`. | 3082     |
| **enc_out_host** | The target address that will receive UDP packets from this application after they have been processed (either encrypted or decrypted). Encrypted packets will be sent on port `enc_out_port` and decrypted packets sent on `dec_out_port` | `host` |
| **enc_out_port** | The port on the target address where encrypted packets will be sent. | 3082     |
| **dec_out_host** | The target address that will receive UDP packets from this application after they have been decrypted. Encrypted packets will be sent on port `enc_out_port` and decrypted packets sent on `dec_out_port` | `host` |
| **dec_out_port** | The port on the target address where decrypted packets will be sent. The application that accepts the decrypted packets should be listening on this port ( e.g. VLC for video ). | 5000     |
| **rotate**       | The number of packets to process for each encryption key. Note that a number that is too low may increase latency. | 9000     |
| **user**         | The XQ account to use. If an email address is specified (e.g. email@domain.com ), the confirmation code sent to that email address will need to be entered. Otherwise, if a simple name alias is entered, an XQ anonymous email address is used based on that alias. | xq-proxy |
| **recipients**   | A comma delimited list of email addresses (not names) that are allowed to view this stream. By default, this will be configured to the email address of the **user** ( if an alias was used, the actual address will be detected). ||
| **config**   | The path to the xq configuration file to use. By default, an `xq.ini` config file is expected to be located in the application directory. | xq.ini |
