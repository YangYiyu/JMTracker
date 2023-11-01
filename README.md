# JMTracker
JMTracker is a tool that automatically tracks the Java method calls within an Android app. It can extract the names and parameter values of Java methods executed by the ART virtual machine during the app's runtime, and build them into a hierarchical method chain.

![JMTracker](https://github.com/YangYiyu/JMTracker/assets/20296244/21cfd7c1-7586-48f8-9829-f3143b4731b2)

# Installation
- Install Python dependency libraries. It is recommended to perform installation in a separate virtual environment.
  ```
  pip3 install -r requirements.txt
  ```

- [Flash](https://source.android.com/docs/setup/build/running#flashing-a-device) the customized Android system image which in the `/aosp` folder into an Android smartphone.

  - We currently only offer the Android 10 image. If you require a different version of the system, you can refer to our tutorial to [costumize](https://github.com/YangYiyu/JMTracker/wiki/Customizing-ART-virtual-machine-of-AOSP), [compile and flash](https://github.com/YangYiyu/JMTracker/wiki/Compile-and-flash-AOSP-image) AOSP image on your own.
  - Make sure that the [Android SDK tools](https://developer.android.google.cn/studio/releases/platform-tools) are properly installed and configured on your computer.

- Connect your smartphone to the computer, enter `adb` interactive mode, and start the `frida-server`.
  ```
  adb shell su 0 "/data/local/tmp/frida-server-12.11.18-android-arm64"
  ```

- Start the JMTracker service and access it through a browser by visiting: http://127.0.0.1:8000/
  ```
  python MainWebService.py
  ```

For information on how to use JMTracker and analysis example, please refer to the [website](https://sites.google.com/view/sharingthreats/) of the paper.
